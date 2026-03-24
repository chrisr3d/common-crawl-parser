# onion-crawler

A Rust program that extracts `.onion` addresses from [Common Crawl](https://commoncrawl.org/) WARC archives.

This project is also a **hands-on Rust tutorial** — each step introduces new language concepts with well-commented code and a learning journal (`PROGRESS.md`) explaining the reasoning behind every pattern used.

## Purpose

Common Crawl provides petabytes of web archive data stored as WARC (Web ARChive) files. This tool downloads those archives, parses them, and extracts any `.onion` (Tor hidden service) addresses found in the crawled content.

## Features

The project was built incrementally and now features the following:

1. **Read WARC paths** — Parse an input file listing WARC archive URIs (plain text or `.gz`)
2. **HTTP download** — Fetch WARC archives from Common Crawl servers
3. **WARC parsing** — Decompress gzip-compressed archives and parse WARC records
4. **Onion extraction** — Use regex to find `.onion` addresses in page content
5. **Deduplication & output** — Deduplicate results and produce structured JSON output
6. **Concurrent processing** — Download and parse multiple archives in parallel with async/tokio

Additional features:

7. **CLI with `clap`** — Short flags (`-l`, `-j`, `-d`), auto `--help`, required input file
8. **Timing** — Per-archive download/parse duration and averages in summary

## Rust Concepts Covered

Each step introduces new Rust fundamentals:

- Error handling with `Result` and `Option`
- Buffered I/O and iterators
- Pattern matching
- Adding and using external crates
- Async programming with `tokio`
- Regex and string processing
- Concurrency patterns

See `[PROGRESS.md](documentation/PROGRESS.md)` for detailed explanations of each concept as they are introduced.

## Build & Run

Requires Rust 1.91+ (edition 2024).

```sh
cargo build                                    # compile (debug)
cargo build --release                          # compile (optimized — ~16s per 1GB archive)
cargo run -- warc.paths                        # download & parse all archives
cargo run -- warc.paths.gz                     # same, from gzipped paths file
cargo run -- warc.paths -l 3                   # process up to 3 archives
cargo run -- warc.paths -j 2                   # 2 concurrent downloads (default: CPU cores)
cargo run -- warc.paths -d                     # delete archive after parsing
cargo run -- warc.paths.gz -l 3 -j 2 -d       # combined (short flags)
cargo run -- warc.paths --limit 3 --jobs 2 --delete  # combined (long flags)
cargo run -- --help                            # show usage and all options
```
