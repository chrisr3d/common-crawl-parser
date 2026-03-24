# onion-crawler

Rust learning project that extracts `.onion` addresses from Common Crawl WARC archives.

## Build & Run

```sh
cargo build                                    # compile
cargo run -- warc.paths                        # download & parse all archives
cargo run -- warc.paths.gz                     # same, from gzipped paths file
cargo run -- warc.paths -l 3                   # process up to 3 archives
cargo run -- warc.paths -j 2                   # 2 concurrent downloads (default: CPU cores)
cargo run -- warc.paths -d                     # delete archive after parsing
cargo run -- warc.paths.gz -l 3 -j 2 -d       # combined (short flags)
cargo run -- warc.paths --limit 3 --jobs 2 --delete  # combined (long flags)
cargo run -- --help                            # show usage and all options
```

## Constraints

- **Teaching project**: code should be idiomatic Rust with clear comments explaining concepts
- **Edition 2024** (rustc 1.91+)
- Progress tracked in `PROGRESS.md`

## Current State

Steps 1–6 complete: full async pipeline from reading WARC paths → concurrent HTTP
downloads → pipelined WARC parsing → `.onion` regex extraction → deduplication → JSON
output. Three-state processing model (processed → skip, downloaded → parse, missing →
download + parse). Multiple archives download in parallel (configurable `-j N`,
default: CPU core count), and parsing starts immediately when each download completes via
`spawn_blocking`. Results stored in `output/onions.json`, processing state tracked in
`output/processed.log`.

Code is split into two files: `src/main.rs` (CLI parsing + pipeline orchestration) and
`src/lib.rs` (download, parse, and state management). CLI uses `clap` derive for
argument parsing with short flags (`-l`, `-j`, `-d`) and auto-generated `--help`.
Input paths file is a required positional argument and supports gzip-compressed
`.gz` files (decompressed transparently via `libflate`). Per-archive timing reports
download and parse durations, with averages in the final summary.

Dependencies: `clap` (CLI parsing), `reqwest` (async HTTP), `tokio` (async runtime),
`futures` (stream utilities), `warc` (structured WARC parsing), `regex`, `serde_json`,
`libflate` (gzip decompression for paths file).

Performance: `[profile.dev.package."*"] opt-level = 2` optimizes dependencies in debug
builds. Regex is case-sensitive (`(?i)` flag causes 1000x+ slowdown with `\b` boundaries).
Release build parses a 1GB archive in ~16s.

## Roadmap

1. ~~Project scaffolding — read WARC paths file~~ (done)
2. ~~HTTP download of WARC archives~~ (done)
3. ~~Gzip decompression + WARC record parsing~~ (done)
4. ~~Regex extraction of `.onion` addresses~~ (done)
5. ~~Deduplication and output formatting~~ (done)
6. ~~Concurrent downloads with async/tokio~~ (done)
