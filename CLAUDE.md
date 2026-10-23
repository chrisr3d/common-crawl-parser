# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Rust learning project (crate `cc-extract`) that extracts Artifacts (`.onion` addresses, favicon URLs) from Common Crawl WARC archives. Teaching-oriented: code should be idiomatic Rust with clear comments explaining concepts. Edition 2024 (rustc 1.91+). Progress tracked in `documentation/PROGRESS.md`.

## Commands

```sh
cargo build                    # compile (debug)
cargo build --release          # compile (optimized)
cargo test                     # run all tests
cargo test --lib               # run only library tests (skip integration tests)
cargo clippy                   # lint
cargo fmt                      # format
cargo fmt -- --check           # check formatting without modifying
cargo run -- warc.paths -l 3   # process 3 archives (needs warc.paths file)
cargo run -- warc.paths -e onion -t memory  # onions only, parsed from memory
cargo run -- merge output/1 output/2        # merge several --output-dir runs into output/
cargo run -- --help            # show all CLI options
cargo run --release --example baseline -- <archive.warc.gz>  # original warc-crate parser, as a benchmark
```

Key CLI flags: `-l` (limit archives), `-o` (offset), `-j` (concurrent jobs), `-d` (delete after parse), `-e` (Artifact kinds, comma-separated, default `onion,favicon`), `-t` (Transport: disk/memory/mmap), `--onion-engine` (memchr/regex), `--output-dir`.

## Architecture

Parsing separates three independent choices: Transport (how bytes arrive), Format (how records are read, WARC only for now), Artifact kind (what is extracted). Vocabulary in `GLOSSARY.md`.

- **`src/main.rs`** -- CLI parsing (`clap` derive), scheduling (per Shard, the requested kinds not yet done), pipeline orchestration, concurrent task dispatch via `buffer_unordered`. Maps `-t` (fieldless `TransportChoice`) to a `Transport` per task and builds one extractor per missing kind (`new_extractor`). `merge` subcommand loops over every `ArtifactKind`. Contains platform-specific `get_available_memory()` behind `#[cfg(target_os)]`.
- **`src/lib.rs`** -- `Transport { Disk(PathBuf), Memory(Vec<u8>), Mmap(PathBuf) }` and `parse_archive(transport, &shard, &mut extractors)`, the one parsing loop; async download (`reqwest`); state management per kind: `load_processed_from` (`HashSet<(Shard, ArtifactKind)>` from `<shard> <kind>` lines in `output/processed.log`), `load_sightings_from` / `save_sightings_to` / `merge_sightings_from`, and `save_then_mark` (save the kind's file, then append the line: the only way to mark a pair done). Re-exports the main types at the crate root.
- **`src/artifact.rs`** -- `ArtifactKind` (clap `ValueEnum`: one name for CLI, `Display` and `processed.log`; `output_filename()`), `Shard` (Archive name without `.warc.gz`), `Sighting { page_url, date, shard }`, `Sightings` map, and the only dedup logic (`add_sightings`, `merge_sightings`).
- **`src/extractor.rs`** -- `trait Extractor` (one boxed extractor per kind per Shard), `OnionExtractor` (engine `Memchr | Regex`), `FaviconExtractor`. The parsing loop never names a kind.
- **`src/page_record.rs`** -- `PageRecord<'a>` (one variant per Format, `Warc(WarcResponse)` today) borrowing the parser's bytes; HTML detection via `WarcResponse::html_body()`.
- **`src/warc_parser.rs`** -- Custom byte-level WARC record parser. `WarcRecordIter<R: BufRead>` for streaming, `WarcSliceIter<'a>` for mmap. Skips non-response record bodies for performance.
- **`src/onion_search.rs`** -- `ONION_PATTERN` (ASCII word boundaries) and the two engines: `search_regex_bytes()` (regex::bytes) and `search_memchr()` (SIMD memmem). Both return `Vec<String>`.
- **`src/favicon_search.rs`** -- Byte-level `<link>`/`<meta>` favicon scanner. Declared favicons only, no root `/favicon.ico` guess (ADR-0003).

**Data flow**: Read paths file -> schedule each Shard with its requested kinds not yet done -> concurrent download (async) -> `spawn_blocking` parse (CPU-bound) -> merge results sequentially -> per kind: save JSON, then mark `<shard> <kind>` done.

**Transports and onion engines**: `-t disk` (default), `-t memory`, `-t mmap`; `--onion-engine memchr` (default) or `regex`. All combinations give identical results. The original `warc`-crate parser lives in `examples/baseline.rs` (`warc` is a dev-dependency).

**Output**: `output/onions.json` and `output/favicons.json` (only requested kinds are loaded and saved) -- nested JSON mapping each Artifact to a list of `Sighting` (page_url, date, shard). Deduplicated on `(page_url, shard)` pairs. `output/processed.log`: one `<shard> <kind>` line per done pair; lines without a known kind are ignored.

## Performance notes

- `[profile.dev.package."*"] opt-level = 2` optimizes dependencies in debug builds
- Regex must be case-sensitive -- `(?i)` with `\b` causes 1000x+ slowdown
- `flate2` uses `zlib-ng` backend for SIMD gzip decompression
- Resource guards cap concurrency at `min(requested_jobs, 2x CPU cores, available_RAM / 1GB)` (the RAM cap only with `-t memory`)

## Agent skills

### Issue tracker

Issues live as local markdown files under `.scratch/<feature-slug>/`. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five canonical roles (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`), recorded as a `Status:` line in each issue file. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` + `docs/adr/` at repo root. See `docs/agents/domain.md`.
