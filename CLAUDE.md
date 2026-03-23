# onion-crawler

Rust learning project that extracts `.onion` addresses from Common Crawl WARC archives.

## Build & Run

```sh
cargo build              # compile
cargo run                # download & parse 1 archive (default)
cargo run -- --limit 3   # process up to 3 archives
cargo run -- --delete    # delete archive after parsing
cargo run -- --limit 3 --delete custom.paths  # combined
```

## Constraints

- **Teaching project**: code should be idiomatic Rust with clear comments explaining concepts
- **Edition 2024** (rustc 1.91+)
- Progress tracked in `PROGRESS.md`

## Current State

Steps 1–5 complete: sequential pipeline from reading WARC paths → HTTP downloads (ureq)
→ WARC parsing → `.onion` regex extraction → deduplication → JSON output. Three-state
processing model (processed → skip, downloaded → parse, missing → download + parse).
Results stored in `output/onions.json`, processing state tracked in
`output/processed.log`. Uses `ureq` (blocking HTTP), `warc` (structured WARC parsing),
`regex`, `serde_json`.

Performance: `[profile.dev.package."*"] opt-level = 2` optimizes dependencies in debug
builds. Regex is case-sensitive (`(?i)` flag causes 1000x+ slowdown with `\b` boundaries).
Release build parses a 1GB archive in ~16s.

## Roadmap

1. ~~Project scaffolding — read WARC paths file~~ (done)
2. ~~HTTP download of WARC archives~~ (done)
3. ~~Gzip decompression + WARC record parsing~~ (done)
4. ~~Regex extraction of `.onion` addresses~~ (done)
5. ~~Deduplication and output formatting~~ (done)
6. Concurrent downloads with async/tokio
