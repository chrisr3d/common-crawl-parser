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
cargo run -- merge output/1 output/2        # merge several --output-dir runs into output/
cargo run -- --help            # show all CLI options
cargo run --release --example baseline -- <archive.warc.gz>  # original warc-crate parser, as a benchmark
```

Key CLI flags: `-l` (limit Shards), `-o` (offset), `-j` (concurrent jobs), `-d` (delete a Shard's Archives after parse), `-e` (Artifact kinds, comma-separated, default `onion,favicon`; `inline-favicon` only when asked), `--formats` (force the Plan, comma-separated `warc,wat,wet`), `-t` (Transport: disk/memory/mmap), `--onion-engine` (memchr/regex), `--output-dir`.

## Architecture

Parsing separates three independent choices: Transport (how bytes arrive), Format (how records are read: WARC, WAT, WET), Artifact kind (what is extracted). Which Formats a Shard downloads is the planner's choice: the cheapest combination serving every requested kind. Vocabulary in `GLOSSARY.md`.

- **`src/main.rs`** -- CLI parsing (`clap` derive), scheduling (per Shard, the requested kinds not yet done, their `Plan` and the Plan's `ArchivePath`s), pipeline orchestration, concurrent task dispatch via `buffer_unordered` (one task per Shard: `fetch` each Archive, then `parse_archives` in `spawn_blocking`). Maps `-t` (fieldless `TransportChoice`) to a `Transport` per Archive and builds, per Archive, one extractor per kind reading its Format (`new_extractor`). `merge` subcommand loops over every `ArtifactKind`. `main` returns an `ExitCode`: 0 all done, 3 (`EXIT_UNDONE`) when a Shard is left with a kind undone (failed download, parse or save), 1 on early stops (`process::exit`, all before any download), 2 is clap's for invalid arguments; `--help` lists them (`after_long_help`). Contains platform-specific `get_available_memory()` behind `#[cfg(target_os)]`. The `///` comments on `Config` / `Command` are the `-h` text, which README's Usage section shows verbatim: change both together (`tests/cli_help.rs` fails otherwise).
- **`src/lib.rs`** -- `Transport { Disk(PathBuf), Memory(Vec<u8>), Mmap(PathBuf) }` and `parse_archive(transport, format, &shard, &mut extractors)`, the one parsing loop (`to_page_record`: WAT records not made from a `response`, or with unreadable JSON, are skipped); `parse_mmap` (decompresses into `<file name>.<pid>.mmap`, opened with `create_new` and, on Unix, unlinked at once, then maps that open, nameless file: no other process sees it, a kill leaves nothing; Windows keeps the name until return through `TempFile`); async download (`reqwest`): `download_archive` (the one check for an Archive already at `download_path`; streams through `save_archive`, which writes `<file name>.<pid>.part` and renames it once complete and matching `Content-Length`) and `download_archive_to_memory`; `TempFile`, a `Drop` guard removing a temporary file however its function ends, unless `keep` was called once it was renamed (partial download, results `.tmp`); state management per kind, each kind's results a `Findings`: `load_processed_from` (`HashSet<(Shard, ArtifactKind)>` from `<shard> <kind>` lines in `output/processed.log`), `load_sightings_from` / `save_sightings_to` (writes `<file>.tmp`, then renames it over the results file) / `merge_sightings_from`, and `save_then_mark` (save the kind's file, then append the line: the only way to mark a pair done). Re-exports the main types at the crate root.
- **`src/artifact.rs`** -- `ArtifactKind` (clap `ValueEnum`: one name for CLI, `Display` and `processed.log`; `output_filename()`; `format_requirement()`, the `const fn` table of accepted Format combinations: `onion` WARC or WAT + WET, `favicon` WARC or WAT, `inline-favicon` WARC), `Shard` (Archive name without its Format suffix), `Sighting { page_url, date, shard }`, `Sightings` map, `Findings` (one kind's results: `Sightings` or `InlineFavicons`, `#[serde(untagged)]`; `empty(kind)` says which), `ArtifactEntry` (a map value holding Sightings: `Vec<Sighting>` or `InlineFavicon`), and the only dedup logic (`ArtifactEntry::add_sighting`, `add_sightings`, generic `merge_sightings`).
- **`src/inline_favicon.rs`** -- `InlineFavicon { mmh3, media_type, data, sightings }` (saved under `sha256_hex` of the image), `InlineFavicons` map; hand-written base64 encoder, MurmurHash3 x86_32 and Shodan's favicon hash (`mmh3` of Python-style line-wrapped base64, signed); SHA-256 from `sha2`.
- **`src/format.rs`** -- `Format { Warc, Wat, Wet }` (clap `ValueEnum`; suffix, directory, record type, estimated size), `FormatSet` (bitmask set of Formats, `subsets()`), `Dataset { CcMain, CcNews }` (from the path prefix; available Formats), `ArchivePath` (one paths file line; `in_format` derives the other Formats' paths).
- **`src/plan.rs`** -- the planner: `cheapest_fit` (a kind's cheapest combination inside some Formats), `cheapest_plan` (cheapest subset of the Dataset's Formats serving every kind), `Plan` (what each kind reads; `new` with optional `--formats`, `within`, `kinds_reading`, `split_done`: a kind is done only once every Archive it reads parsed), `PlanError`.
- **`src/extractor.rs`** -- `trait Extractor` (one boxed extractor per kind per Archive; a kind reading several Archives has its Sightings unioned), `OnionExtractor` (engine `Memchr | Regex`; searches the WARC HTTP response, the raw WAT JSON, the WET text), `FaviconExtractor` (WARC HTML body, WAT `Head`; nothing in WET), `InlineFaviconExtractor` (WARC HTML body only). The parsing loop never names a kind.
- **`src/page_record.rs`** -- `PageRecord<'a>` (one variant per Format: `Warc(WarcResponse)`, `Wat(WatMetadata)`, `Wet(WetConversion)`) borrowing the parser's bytes; HTML detection via `WarcResponse::html_body()`. `WatMetadata::parse`: `memmem` prefilter for `"WARC-Type":"response"`, then one `serde_json` parse into partial structs borrowing from the record (`Cow<'a, str>`), down to `Head { base, links, metas }`; crawl date from `Envelope.WARC-Header-Metadata.WARC-Date`.
- **`src/warc_parser.rs`** -- Custom byte-level WARC record parser. `WarcRecordIter<R: BufRead>` for streaming, `WarcSliceIter<'a>` for mmap. Both keep one `WARC-Type` (`Format::record_type`: `response` for WARC, `metadata` for WAT, `conversion` for WET) and skip other records' bodies for performance.
- **`src/onion_search.rs`** -- `ONION_PATTERN` (ASCII word boundaries) and the two engines: `search_regex_bytes()` (regex::bytes) and `search_memchr()` (SIMD memmem). Both return `Vec<String>`.
- **`src/favicon_search.rs`** -- Byte-level `<link>`/`<meta>` favicon scanner for WARC (URLs, and base64 `data:` URIs decoded with their media type: `InlineImage`), resolving against the first `<base href>` (scanned only once a favicon URL is found); `favicons_in_head` applies the same rules to a WAT `Head` (resolves against `Head.Base`, skips the truncated `data:` URLs). Declared favicons only, no guessed root `/favicon.ico` (unverified, and one per page).

**Data flow**: Read paths file (WARC, WAT or WET) -> schedule each Shard with its requested kinds not yet done -> plan its Formats, derive the Plan's Archive paths -> concurrent per-Shard tasks: download each Archive (async), then `spawn_blocking` parse each with the extractors of the kinds reading its Format (CPU-bound) -> merge results sequentially -> per kind whose Archives all parsed: save JSON, then mark `<shard> <kind>` done.

**Transports and onion engines**: `-t disk` (default), `-t memory`, `-t mmap`; `--onion-engine memchr` (default) or `regex`. All combinations give identical results. The original `warc`-crate parser lives in `examples/baseline.rs` (`warc` is a dev-dependency).

**HPC**: `examples/slurm/crawl.sh` (SLURM array job, several processes per node, each with its own `--offset` / `--limit` / `--output-dir`, `--transport memory`) and `examples/slurm/merge.sh` (`merge` of every `<output root>/<task>/<process>/`). Setup-neutral: `<...>` placeholders for account, partition and paths; keep cluster-specific values out of them.

**Output**: `output/onions.json`, `output/favicons.json` and `output/inline_favicons.json` (only requested kinds are loaded and saved) -- nested JSON mapping each Artifact to a list of `Sighting` (page_url, date, shard); `inline_favicons.json` maps each image's SHA-256 to `{ mmh3, media_type, data (base64), sightings }`. Deduplicated on `(page_url, shard)` pairs. `output/processed.log`: one `<shard> <kind>` line per done pair; lines without a known kind are ignored.

## Performance notes

- `[profile.dev.package."*"] opt-level = 2` optimizes dependencies in debug builds
- Regex must be case-sensitive -- `(?i)` with `\b` causes 1000x+ slowdown
- `flate2` uses `zlib-ng` backend for SIMD gzip decompression
- Resource guards cap concurrency at `min(requested_jobs, 2x CPU cores, available_RAM / largest estimated Plan)` (the RAM cap only with `-t memory`; estimates: WARC 1 GB, WAT 170 MB, WET 70 MB)

## Agent skills

### Issue tracker

Issues live as local markdown files under `.scratch/<feature-slug>/`. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five canonical roles (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`), recorded as a `Status:` line in each issue file. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` + `docs/adr/` at repo root. See `docs/agents/domain.md`.
