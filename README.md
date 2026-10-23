# cc-extract

A Rust program that extracts Artifacts, such as `.onion` addresses and favicon URLs, from [Common Crawl](https://commoncrawl.org/) WARC archives.

This project is also a **hands-on Rust tutorial** — each step introduces new language concepts with well-commented code and a learning journal (`PROGRESS.md`) explaining the reasoning behind every pattern used.

## Purpose

Common Crawl provides petabytes of web archive data stored as WARC (Web ARChive) files. This tool downloads those archives, parses them, and extracts the requested Artifact kinds from the crawled content: `.onion` (Tor hidden service) addresses and the favicon URLs that HTML pages declare.

## Features

The project was built incrementally and now features the following:

1. **Read WARC paths** — Parse an input file listing WARC archive URIs (plain text or `.gz`)
2. **HTTP download** — Fetch WARC archives from Common Crawl servers
3. **WARC parsing** — Decompress gzip-compressed archives and parse WARC records
4. **Onion extraction** — Use regex to find `.onion` addresses in page content
5. **Deduplication & output** — Deduplicate results and produce structured JSON output
6. **Concurrent processing** — Download and parse multiple archives in parallel with async/tokio
7. **Ripgrep-style parsing** — Transport (`-t`) and onion search engine (`--onion-engine`) selectable at runtime
8. **WARC metadata extraction** — Track source URL, crawl date, and archive for each `.onion` found
9. **In-memory parsing** — Parse from memory with `--transport memory` to skip disk I/O entirely
10. **Resource guards** — Layered concurrency caps (CPU cores, available RAM) prevent oversubscription and OOM
11. **Incremental extraction** — Pick Artifact kinds with `-e`; a later run adds kinds without redoing the ones already done

Additional features:

- **CLI with `clap`** — Short flags (`-l`, `-o`, `-j`, `-d`, `-e`, `-t`), auto `--help`, required input file
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
cargo run -- warc.paths -e onion               # extract onions only (default: onion,favicon)
cargo run -- warc.paths -e onion,favicon       # later: adds favicons, skips the onion work done
cargo run -- warc.paths -t disk                # parse from the downloaded file (default)
cargo run -- warc.paths -t memory              # parse from memory (no disk I/O)
cargo run -- warc.paths -t mmap                # decompress + mmap (needs disk space)
cargo run -- warc.paths --onion-engine regex   # regex::bytes instead of memchr (default)
cargo run -- warc.paths.gz -l 3 -j 2 -d        # combined (short flags)
cargo run -- warc.paths.gz -l 3 -j 2 -t memory -e onion  # combined with in-memory parsing
cargo run -- warc.paths --limit 3 --jobs 2 --delete --transport disk  # combined (long flags)
cargo run -- merge output/1 output/2 -o output # merge results of several --output-dir runs
cargo run -- --help                            # show usage and all options
cargo run --release --example baseline -- download/X.warc.gz  # original parser, as a benchmark
```

## Transports and Onion Engines

Two ripgrep-inspired choices, selectable at runtime. Every combination gives the same
results. The original approach (`warc` crate + `regex::Regex` on UTF-8 strings, ~16s/GB) is
kept as a benchmark: `cargo run --release --example baseline -- <archive.warc.gz>`.

`-t` / `--transport` picks how a downloaded Archive reaches the parser:

| Transport | Technique |
|-----------|-----------|
| `disk` (default) | Download to `download/`, stream-decompress the file |
| `memory` | Download into a `Vec<u8>`, stream-decompress through a `Cursor` (no disk I/O) |
| `mmap` | Download to `download/`, decompress to a temp file, memory-map it (zero-copy) |

`--onion-engine` picks how `.onion` addresses are found:

| Onion engine | Technique | Speedup vs baseline |
|--------------|-----------|---------------------|
| `memchr` (default) | Custom parser + SIMD `memmem` literal search | ~3-5x |
| `regex` | Custom parser + `regex::bytes` on raw `&[u8]` | ~1.5-2x |

Key optimizations: custom WARC parser skips non-response bodies (~60% of data), SIMD
literal search replaces the regex engine, `zlib-ng` backend for faster gzip decompression.

The `memory` Transport costs ~800 MB per archive × concurrent jobs. Layered resource guards
automatically cap concurrency: jobs are limited to 2× CPU cores, and with `--transport
memory`, further limited by available RAM (queried at startup on macOS and Linux) to
prevent OOM.

## Output Format

Each Artifact kind has its own file: `output/onions.json` and `output/favicons.json`, as
nested JSON. Each Artifact (a `.onion` address, a favicon URL) maps to a list of Sightings:
the clearnet page where it was found, the crawl date, and the Shard (the Archive file name
without `.warc.gz`):

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

`output/processed.log` records which (Shard, Artifact kind) pairs are done, one
`<shard> <kind>` line each, such as `CC-NEWS-20251001064107-04363 onion`. A run only extracts the
requested kinds not yet done for a Shard, and a pair is recorded only after its results
file is saved. Lines written before kinds were tracked (bare Archive file names) are
ignored, so those Archives are processed again.
