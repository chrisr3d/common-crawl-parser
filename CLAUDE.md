# onion-crawler

Rust learning project that extracts `.onion` addresses from Common Crawl WARC archives.

## Build & Run

```sh
cargo build              # compile
cargo run                # run with default warc.paths
cargo run -- <file>      # run with custom input file
```

## Constraints

- **Teaching project**: code should be idiomatic Rust with clear comments explaining concepts
- **Edition 2024** (rustc 1.91+)
- Progress tracked in `PROGRESS.md`

## Current State

Step 1 complete: reads `warc.paths` line by line, prints each path with line number.

## Roadmap

1. ~~Project scaffolding — read WARC paths file~~ (done)
2. HTTP download of a single WARC file
3. Gzip decompression + WARC record parsing
4. Regex extraction of `.onion` addresses
5. Deduplication and output formatting
6. Concurrent downloads with async/tokio
