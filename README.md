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
7. **Ripgrep-style parsing strategies** — Four optimization layers selectable at runtime (`-s`)
8. **WARC metadata extraction** — Track source URL, crawl date, and archive for each `.onion` found
9. **In-memory streaming** — Parse from memory with `--stream` / `-m` to skip disk I/O entirely
10. **Resource guards** — Layered concurrency caps (CPU cores, available RAM) prevent oversubscription and OOM

Additional features:

- **CLI with `clap`** — Short flags (`-l`, `-j`, `-d`, `-s`, `-m`), auto `--help`, required input file
- **Timing** — Per-archive download/parse duration and averages in summary

## Rust Concepts Covered

Each step introduces new Rust fundamentals:

- Error handling with `Result` and `Option`
- Buffered I/O and iterators
- Pattern matching
- Adding and using external crates
- Async programming with `tokio`
- Regex and string processing
- Concurrency patterns
- Serialization with `serde` derive macros
- In-memory I/O with `std::io::Cursor`
- Conditional compilation with `#[cfg(target_os)]`
- Platform-specific code (macOS `sysctl`, Linux `/proc/meminfo`)
- SIMD-accelerated byte searching (`memchr`)
- Memory-mapped I/O (`mmap`)
- `unsafe` blocks and when they're justified
- Performance optimization and benchmarking strategies

See `[PROGRESS.md](documentation/PROGRESS.md)` for detailed explanations of each concept as they are introduced.

## Build & Run

Requires Rust 1.91+ (edition 2024).

```sh
cargo build                                    # compile (debug)
cargo build --release                          # compile (optimized — ~5.6s per 864MB archive)
cargo run -- warc.paths                        # download & parse all archives
cargo run -- warc.paths.gz                     # same, from gzipped paths file
cargo run -- warc.paths -l 3                   # process up to 3 archives
cargo run -- warc.paths -j 2                   # 2 concurrent downloads (default: CPU cores)
cargo run -- warc.paths -d                     # delete archive after parsing
cargo run -- warc.paths -s memchr              # select parsing strategy (default)
cargo run -- warc.paths -s bytes               # custom parser + regex::bytes
cargo run -- warc.paths -s mmap                # mmap + memchr (needs disk space)
cargo run -- warc.paths -m                     # parse from memory (no disk I/O)
cargo run -- warc.paths -s bytes --stream      # stream mode with bytes strategy
cargo run -- warc.paths.gz -l 3 -j 2 -d       # combined (short flags)
cargo run -- warc.paths.gz -l 3 -j 2 -m -s memchr  # combined with stream mode
cargo run -- warc.paths --limit 3 --jobs 2 --delete --strategy memchr  # combined (long flags)
cargo run -- --help                            # show usage and all options
cargo run --release --example baseline -- download/X.warc.gz  # original parser, as a benchmark
```

## Parsing Strategies

Three ripgrep-inspired optimization layers, selectable at runtime via `-s` / `--strategy`.
The original approach (`warc` crate + `regex::Regex` on UTF-8 strings, ~16s/GB) is kept
as a benchmark: `cargo run --release --example baseline -- <archive.warc.gz>`.

| Strategy | Technique | Speedup vs baseline |
|----------|-----------|---------------------|
| `bytes` | Custom WARC parser + `regex::bytes` on raw `&[u8]` | ~1.5-2x |
| `memchr` (default) | Custom parser + SIMD `memmem` literal search | ~3-5x |
| `mmap` | Decompress to temp file + mmap + zero-copy memchr | ~3-6x |

Key optimizations: custom WARC parser skips non-response bodies (~60% of data), SIMD
literal search replaces the regex engine, `zlib-ng` backend for faster gzip decompression.

The `bytes` and `memchr` strategies also support `--stream` / `-m` mode, which downloads
archives into memory and parses from a `Cursor<Vec<u8>>` instead of a file — eliminating
all disk I/O. The `mmap` strategy needs a file, so it falls back to disk mode with a
warning. Memory cost: ~800 MB per archive × concurrent jobs. Layered resource guards
automatically cap concurrency: jobs are limited to 2× CPU cores, and in stream mode,
further limited by available RAM (queried at startup on macOS and Linux) to prevent OOM.

## Output Format

Results are stored in `output/onions.json` as nested JSON. Each `.onion` address maps to
a list of Sightings: the clearnet page where it was found, the crawl date, and the Shard
(the Archive file name without `.warc.gz`):

```json
{
  "example1234567890.onion": [
    {
      "page_url": "https://example.com/page",
      "date": "2024-09-15T12:34:56Z",
      "shard": "CC-NEWS-20240915"
    }
  ]
}
```

Sighting metadata is extracted from WARC headers (`WARC-Target-URI`, `WARC-Date`) during
parsing. Results are deduplicated on `(page_url, shard)` pairs. Files written before this
shape (with `url` / `archive` fields) are not converted: a run that finds one in its output
directory stops with an error instead of overwriting it.
