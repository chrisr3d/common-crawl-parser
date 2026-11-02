# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Rust learning project (crate `cc-extract`) that extracts Artifacts (`.onion` addresses, favicon URLs, inline favicon images) from Common Crawl WARC archives. Teaching-oriented: code should be idiomatic Rust with clear comments explaining concepts. Edition 2024 (rustc 1.91+). Progress tracked in `documentation/PROGRESS.md`.

## Commands

```sh
cargo build                    # compile (debug)
cargo build --release          # compile (optimized)
cargo test                     # run all tests
cargo test --lib               # run only library tests (skip integration tests)
cargo clippy                   # lint
cargo fmt                      # format
cargo fmt -- --check           # check formatting without modifying
cargo run -- warc.paths -l 3   # process 3 Shards (needs warc.paths file)
cargo run -- warc.paths -e onion -t memory  # onions only, parsed from memory
cargo run -- warc.paths -e onion,inline-favicon  # inline favicons need WARC; onions read it too
cargo run -- wat.paths.gz --formats warc    # any Format's paths file; force the Formats downloaded
cargo run -- warc.paths --kvrocks redis://127.0.0.1:6666  # store over TCP (default: socket /tmp/kvrocks.sock)
CC_EXTRACT_TEST_KVROCKS=redis://127.0.0.1:16666 cargo test  # also run the crawl tests against a THROWAWAY kvrocks (they FLUSHDB it)
cargo run -- --help            # show all CLI options
cargo run --release --example baseline -- <archive.warc.gz>  # original warc-crate parser, as a benchmark
```

Key CLI flags: `-l` (limit Shards), `-o` (offset), `-j` (concurrent jobs), `-d` (delete a Shard's Archives after parse), `-e` (Artifact kinds, comma-separated, default `onion,favicon`; `inline-favicon` only when asked), `--formats` (force the Plan, comma-separated `warc,wat,wet`), `-t` (Transport: disk/memory/mmap), `--onion-engine` (memchr/regex), `--kvrocks` (the store: a Unix socket path or `redis://host:port`; password only from `CC_EXTRACT_KVROCKS_PASSWORD`).

## Architecture

Parsing separates three independent choices: Transport (how bytes arrive), Format (how records are read: WARC, WAT, WET), Artifact kind (what is extracted). Which Formats a Shard downloads is the planner's choice: the cheapest combination serving every requested kind. Vocabulary in `GLOSSARY.md`.

- **`src/main.rs`** -- CLI parsing (`clap` derive; no subcommand), scheduling (per Shard, the requested kinds not yet done, their `Plan` and the Plan's `ArchivePath`s), pipeline orchestration, concurrent task dispatch via `buffer_unordered` (one task per Shard: `fetch` each Archive, then `parse_archives` in `spawn_blocking`). One `HttpClient::new(READ_TIMEOUT)` shared by all tasks. Connects `KvrocksStore` after the paths file is read, before any download (unreachable: exit 1), reads the done pairs (`load_processed`); the result loop calls `save_then_mark` per done kind (failure: pair undone) and logs `Store time`; totals from `artifact_count`. Maps `-t` (fieldless `TransportChoice`) to a `Transport` per Archive and builds, per Archive, one extractor per kind reading its Format (`new_extractor`). `main` returns an `ExitCode`: 0 all done, 3 (`EXIT_UNDONE`) when a Shard is left with a kind undone (failed download, parse or store write), 1 on early stops (`process::exit`, all before any download; unreachable store included), 2 is clap's for invalid arguments (a `--kvrocks` URL `StoreAddress` refuses included); `--help` lists them (`after_long_help`). Contains platform-specific `get_available_memory()` behind `#[cfg(target_os)]`. The `///` comments on `Config` are the `-h` text, which README's Usage section shows verbatim: change both together (`tests/cli_help.rs` fails otherwise).
- **`src/lib.rs`** -- `Transport { Disk(PathBuf), Memory(Vec<u8>), Mmap(PathBuf) }` and `parse_archive(transport, format, &shard, &mut extractors)`, the one parsing loop (`to_page_record`: WAT records not made from a `response`, or with unreadable JSON, are skipped); `parse_mmap` (decompresses into `<file name>.<pid>.mmap`, opened with `create_new` and, on Unix, unlinked at once, then maps that open, nameless file: no other process sees it, a kill leaves nothing; Windows keeps the name until return through `TempFile`); async download (`reqwest`) through `HttpClient` (`new(read_timeout)`, the one client a run shares, built here: connect timeout 30 s, and a read timeout, `READ_TIMEOUT` (60 s) in the crawl, failing a download that receives no data for that long with `no data received for <bound> s`): `download_to` (a URL to a local path; the one check for an Archive already there; streams through `save_archive`, which writes `<file name>.<pid>.part` and renames it once complete and matching `Content-Length`) and `download_to_memory`, which `download_archive` / `download_archive_to_memory` call with the Common Crawl URL and `download_path`; `TempFile`, a `Drop` guard removing a temporary file however its function ends, unless `keep` was called once it was renamed (partial download, mmap copy on Windows). Re-exports the main types at the crate root.
- **`src/store.rs`** -- the results store (kvrocks). `trait Store` (methods return `impl Future + Send`: `write(&[Write])` pipelined, replies say what changed; `members` / `fields` / `count`), `Write { SetAdd, HashSetIfAbsent }` (only adding: `SADD`, `HSETNX`, so every write is idempotent). Adapters: `KvrocksStore` (`redis` crate, `MultiplexedConnection`, `connect` sends `AUTH` with the password if any, then `PING`) and `MemoryStore` (test double; `fail_after(n)` makes later writes fail; `PartialEq` compares every key). Generic over `impl Store`: `save_then_mark` (a kind's `Findings` for one Shard in batches of `BATCH_SIZE`, then `<shard> <kind>` added to `processed`: the only way to mark a pair done; adds to a `&mut usize` the Artifacts new to `artifacts:<kind>`, so batches acknowledged before a failure still count), `load_processed` (`HashSet<(Shard, ArtifactKind)>`; unknown kinds ignored), `artifact_count`. Keys: `page:<id>` (hash; id = first 16 bytes of SHA-256 of `"<shard> <page_url>"`, hex), `<kind>:<artifact>`, `page:<id>:<kind>`, `artifacts:<kind>`, `image:<sha256>` (`media_type`, `mmh3`), `processed`. `StoreAddress` (`--kvrocks`: a socket path, or `redis://host:port`; a password in the URL refused), `DEFAULT_SOCKET`, `PASSWORD_VARIABLE`.
- **`src/artifact.rs`** -- `ArtifactKind` (clap `ValueEnum`: one name for CLI, `Display` and the store's keys and done marks; `format_requirement()`, the `const fn` table of accepted Format combinations: `onion` WARC or WAT + WET, `favicon` WARC or WAT, `inline-favicon` WARC), `Shard` (Archive name without its Format suffix), `Sighting { page_url, date, shard }`, `Sightings` map, `Findings` (one kind's results in one Shard: `Sightings` or `InlineFavicons`; `empty(kind)` says which), `ArtifactEntry` (a map value holding Sightings: `Vec<Sighting>` or `InlineFavicon`), and the within-Shard dedup logic (`ArtifactEntry::add_sighting`, `add_sightings`, generic `merge_sightings`); across Shards the store's sets dedup.
- **`src/inline_favicon.rs`** -- `InlineFavicon { mmh3, media_type, data, sightings }` (kept under `sha256_hex` of the image; the store keeps `mmh3` and `media_type`, not `data`), `InlineFavicons` map; hand-written base64 encoder, MurmurHash3 x86_32 and Shodan's favicon hash (`mmh3` of Python-style line-wrapped base64, signed); SHA-256 from `sha2`.
- **`src/format.rs`** -- `Format { Warc, Wat, Wet }` (clap `ValueEnum`; suffix, directory, record type, estimated size), `FormatSet` (bitmask set of Formats, `subsets()`), `Dataset { CcMain, CcNews }` (from the path prefix; available Formats), `ArchivePath` (one paths file line; `in_format` derives the other Formats' paths).
- **`src/plan.rs`** -- the planner: `cheapest_fit` (a kind's cheapest combination inside some Formats), `cheapest_plan` (cheapest subset of the Dataset's Formats serving every kind), `Plan` (what each kind reads; `new` with optional `--formats`, `within`, `kinds_reading`, `split_done`: a kind is done only once every Archive it reads parsed), `PlanError`.
- **`src/extractor.rs`** -- `trait Extractor` (one boxed extractor per kind per Archive; a kind reading several Archives has its Sightings unioned), `OnionExtractor` (engine `Memchr | Regex`; searches the WARC HTTP response, the raw WAT JSON, the WET text), `FaviconExtractor` (WARC HTML body, WAT `Head`; nothing in WET), `InlineFaviconExtractor` (WARC HTML body only). The parsing loop never names a kind.
- **`src/page_record.rs`** -- `PageRecord<'a>` (one variant per Format: `Warc(WarcResponse)`, `Wat(WatMetadata)`, `Wet(WetConversion)`) borrowing the parser's bytes; HTML detection via `WarcResponse::html_body()`. `WatMetadata::parse`: `memmem` prefilter for `"WARC-Type":"response"`, then one `serde_json` parse into partial structs borrowing from the record (`Cow<'a, str>`), down to `Head { base, links, metas }`; crawl date from `Envelope.WARC-Header-Metadata.WARC-Date`.
- **`src/warc_parser.rs`** -- Custom byte-level WARC record parser. `WarcRecordIter<R: BufRead>` for streaming, `WarcSliceIter<'a>` for mmap. Both keep one `WARC-Type` (`Format::record_type`: `response` for WARC, `metadata` for WAT, `conversion` for WET) and skip other records' bodies for performance.
- **`src/onion_search.rs`** -- `ONION_PATTERN` (any case, ASCII word boundaries), `checked_address` (the one validity check, applied by both engines and `examples/baseline.rs`: v2 kept as is, v3 checksum and version verified with `sha3` over hand-written base32; returns the address lowercase) and the two engines: `search_regex_bytes()` (regex::bytes) and `search_memchr()` (`SuffixFinder`: SIMD memmem for `.o` and `.O`, merged in order). Both return `Vec<String>`.
- **`src/favicon_search.rs`** -- Favicon scanner for WARC: one forward pass (`scan_page`, `memchr` to each `<`) reading `<link>`/`<meta>`/`<base>` by HTML's tokenizer rules (`Attributes`: any case and spacing, bare values to whitespace or `>`, no length cap; entities decoded by `decode_entities`; comments and raw-text elements such as `<script>` skipped), giving URLs and base64 `data:` URIs decoded with their media type (`InlineImage`). `rel` is a token list (`icon`, `apple-touch-icon`, `apple-touch-icon-precomposed`, `mask-icon`); URLs resolve with the `url` crate against the first `<base href>`. `favicons_in_head` applies the same token rule and resolution to a WAT `Head` (resolves against `Head.Base`; no entity decoding or comment skipping, which ia-web-commons has done; drops the truncated `data:` URLs). Declared favicons only, no guessed root `/favicon.ico` (unverified, and one per page).

**Data flow**: Read paths file (WARC, WAT or WET) -> schedule each Shard with its requested kinds not yet done -> plan its Formats, derive the Plan's Archive paths -> concurrent per-Shard tasks: download each Archive (async), then `spawn_blocking` parse each with the extractors of the kinds reading its Format (CPU-bound) -> sequentially, per kind whose Archives all parsed: write its Sightings to the store, then add `<shard> <kind>` to `processed`.

**Transports and onion engines**: `-t disk` (default), `-t memory`, `-t mmap`; `--onion-engine memchr` (default) or `regex`. All combinations give identical results. The original `warc`-crate parser lives in `examples/baseline.rs` (`warc` is a dev-dependency).

**HPC**: `examples/slurm/crawl.sh` (SLURM array job, several processes per node, each with its own `--offset` / `--limit`, `--transport memory`, `--kvrocks`), marked as not working with the store: runs across several nodes are not supported yet. Setup-neutral: `<...>` placeholders for account, partition, paths and store; keep cluster-specific values out of them.

**Output**: the kvrocks store only (keys in `src/store.rs`); no results file, nothing under the working directory but `download/` and the mmap copy. One Sighting = one Page in an Artifact's set, deduplicated on `(page_url, shard)`; first `date` / `media_type` written kept. Inline favicon bytes dropped once hashed. `processed` members without a known kind are ignored. End-to-end tests (`tests/crawl_cli.rs`) need `CC_EXTRACT_TEST_KVROCKS` (skipped otherwise, one at a time, `FLUSHDB` first); library tests use `MemoryStore` (`tests/store.rs`).

## Performance notes

- `[profile.dev.package."*"] opt-level = 2` optimizes dependencies in debug builds
- Onion regex lists both cases per letter (`[a-zA-Z2-7]`, `[oO]`) -- `(?i)` with `\b` caused a 1000x+ slowdown
- `flate2` uses `zlib-ng` backend for SIMD gzip decompression
- Resource guards cap concurrency at `min(requested_jobs, 2x CPU cores, available_RAM / largest estimated Plan)` (the RAM cap only with `-t memory`; estimates: WARC 1 GB, WAT 170 MB, WET 70 MB)

## Agent skills

### Issue tracker

Issues live as local markdown files under `.scratch/<feature-slug>/`. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five canonical roles (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`), recorded as a `Status:` line in each issue file. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` + `docs/adr/` at repo root. See `docs/agents/domain.md`.
