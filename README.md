# cc-extract

A Rust program that extracts Artifacts, such as `.onion` addresses and favicons, from [Common Crawl](https://commoncrawl.org/) archives.

This project is also a **hands-on Rust tutorial** — each step introduces new language concepts with well-commented code and a learning journal (`PROGRESS.md`) explaining the reasoning behind every pattern used.

## Purpose

Common Crawl publishes petabytes of crawled web pages. Each Shard of a Crawl (one file-level slice of it) comes in up to three Formats: WARC (raw HTTP responses, ~1 GB), WAT (JSON metadata extracted from them, ~170 MB) and WET (their plain text, ~70 MB). This tool downloads, for each Shard, the cheapest Formats that hold what was asked for, parses them, and extracts the requested Artifact kinds:

| Artifact kind | What | Formats it can read |
|---------------|------|---------------------|
| `onion` (default) | `.onion` (Tor hidden service) addresses | WARC, or WAT + WET |
| `favicon` (default) | Favicon URLs that HTML pages declare | WARC, or WAT |
| `inline-favicon` | Favicon images that HTML pages embed as base64 `data:` URIs | WARC |

The words used here (Shard, Format, Archive, Artifact, Sighting, Plan) are defined in [`GLOSSARY.md`](GLOSSARY.md).

## Features

The project was built incrementally and now features the following:

1. **Read paths files** — Parse a WARC, WAT or WET paths file (plain text or `.gz`); the other Formats' paths are derived from it
2. **HTTP download** — Fetch each Shard's Archives from Common Crawl servers
3. **Archive parsing** — Decompress gzip-compressed Archives and read their WARC, WAT or WET records with a custom parser
4. **Onion extraction** — Find `.onion` addresses in HTTP responses (WARC), metadata JSON (WAT) or page text (WET)
5. **Favicon extraction** — Find the favicons HTML pages declare, resolved against the page's `<base href>`; inline images are saved with their SHA-256 and Shodan's `mmh3` favicon hash
6. **Deduplication & output** — Deduplicate Sightings and produce one JSON file per Artifact kind
7. **Concurrent processing** — Download and parse several Shards in parallel with async/tokio
8. **Ripgrep-style parsing** — Transport (`-t`) and onion search engine (`--onion-engine`) selectable at runtime
9. **Sighting metadata** — Record the page URL, crawl date and Shard of each Artifact found
10. **In-memory parsing** — Parse from memory with `--transport memory` to skip disk I/O entirely
11. **Resource guards** — Layered concurrency caps (CPU cores, available RAM) prevent oversubscription and OOM
12. **Incremental extraction** — Pick Artifact kinds with `-e`; a later run adds kinds without redoing the ones already done
13. **Format planning** — Per Shard, download only the cheapest Formats that serve every requested kind (`--formats` to force them): on CC-MAIN, `onion` and `favicon` read WAT + WET (~240 MB) instead of WARC (~1 GB), `favicon` alone WAT only
14. **HPC batch mode** — Split a Crawl across processes with `--offset`, `--limit` and `--output-dir`, then `merge` their results; SLURM example in [`examples/slurm/`](examples/slurm/)

Additional features:

- **CLI with `clap`** — Short flags (`-l`, `-o`, `-j`, `-d`, `-e`, `-t`), auto `--help`, paths file as positional argument
- **Timing** — Per-Shard download/parse duration and averages in summary
- **Crash-safe writes** — Results files and downloads are written under a temporary name and renamed once complete: a killed run leaves no file cut short under a name a run reads, and the next run resumes as is

## Rust Concepts Covered

Each step introduces new Rust fundamentals:

- Error handling with `Result` and `Option`
- Buffered I/O and iterators
- Pattern matching, and exhaustive `match` as a table the compiler checks
- Adding and using external crates
- Async programming with `tokio`
- Regex and string processing
- Concurrency patterns
- Serialization with `serde` derive macros, and zero-copy deserialization with `Cow`
- Trait objects (`Box<dyn Extractor>`) and generic functions over a trait
- In-memory I/O with `std::io::Cursor`
- Conditional compilation with `#[cfg(target_os)]`
- Platform-specific code (macOS `sysctl`, Linux `/proc/meminfo`)
- SIMD-accelerated byte searching (`memchr`)
- Memory-mapped I/O (`mmap`)
- `unsafe` blocks and when they're justified
- Cleanup on every error path with a `Drop` guard, and atomic file replacement with `fs::rename`
- Values computed on first use (`OnceCell`, `LazyLock`)
- Performance optimization and benchmarking strategies

See [`PROGRESS.md`](documentation/PROGRESS.md) for detailed explanations of each concept as they are introduced, and [`FEATURES.md`](documentation/FEATURES.md) for what each feature does and where it stops short.

## Build & Run

Requires Rust 1.91+ (edition 2024).

```sh
cargo build                                    # compile (debug)
cargo build --release                          # compile (optimized — ~5.6s per 864MB archive)
cargo run -- warc.paths                        # download & parse every Shard
cargo run -- warc.paths.gz                     # same, from gzipped paths file
cargo run -- warc.paths -l 3                   # process up to 3 Shards
cargo run -- warc.paths -j 2                   # 2 concurrent Shards (default: CPU cores)
cargo run -- warc.paths -d                     # delete each Shard's Archives after parsing
cargo run -- warc.paths -e onion               # extract onions only (default: onion,favicon)
cargo run -- warc.paths -e onion,favicon       # later: adds favicons, skips the onion work done
cargo run -- warc.paths -e onion,inline-favicon  # inline favicons need WARC; onions read it too
cargo run -- wat.paths.gz                      # any Format's paths file: Shards are the same
cargo run -- warc.paths --formats warc         # force the Formats downloaded per Shard
cargo run -- warc.paths -t disk                # parse from the downloaded file (default)
cargo run -- warc.paths -t memory              # parse from memory (no disk I/O)
cargo run -- warc.paths -t mmap                # decompress + mmap (needs disk space)
cargo run -- warc.paths --onion-engine regex   # regex::bytes instead of memchr (default)
cargo run -- warc.paths.gz -l 3 -j 2 -d        # combined (short flags)
cargo run -- warc.paths.gz -l 3 -j 2 -t memory -e onion  # combined with in-memory parsing
cargo run -- warc.paths --limit 3 --jobs 2 --delete --transport disk  # combined (long flags)
cargo run -- warc.paths -o 1000 -l 1000 --output-dir output/1  # one slice of a Crawl
cargo run -- merge output/1 output/2 -o output # merge results of several --output-dir runs
cargo run -- --help                            # show usage and all options
cargo run --release --example baseline -- download/X.warc.gz  # original parser, as a benchmark
```

## Usage

`cc-extract -h` prints:

```text
Extract artifacts, such as .onion addresses and favicon URLs, from Common Crawl archives

Usage: cc-extract [OPTIONS] [INPUT] [COMMAND]

Commands:
  merge  Merge partial results from multiple output directories (HPC post-processing)
  help   Print this message or the help of the given subcommand(s)

Arguments:
  [INPUT]  Path to a WARC, WAT or WET paths file (supports .gz) — omit when using `merge`

Options:
  -l, --limit <LIMIT>                Maximum number of Shards to process (default: all)
  -o, --offset <OFFSET>              Skip the first N paths in the file (for SLURM array partitioning) [default: 0]
  -j, --jobs <JOBS>                  Number of concurrent download+parse tasks (default: number of CPU cores)
  -d, --delete                       Delete each Shard's Archives once parsed
  -e, --extract <EXTRACT>            Artifact kinds to extract, comma-separated [default: onion,favicon] [possible values: onion, favicon, inline-favicon]
      --formats <FORMATS>            Formats to download for every Shard, comma-separated (default: the cheapest ones serving every kind) [possible values: warc, wat, wet]
  -t, --transport <TRANSPORT>        How downloaded Archives reach the parser [default: disk] [possible values: disk, memory, mmap]
      --onion-engine <ONION_ENGINE>  Search used to find .onion addresses [default: memchr] [possible values: memchr, regex]
      --output-dir <OUTPUT_DIR>      Output directory for results and processed log [default: output]
  -h, --help                         Print help (see more with '--help')
```

and `cc-extract merge -h`:

```text
Merge partial results from multiple output directories (HPC post-processing)

Usage: cc-extract merge [OPTIONS] <INPUT_DIRS>...

Arguments:
  <INPUT_DIRS>...  Directories containing partial results files to merge

Options:
  -o, --output-dir <OUTPUT_DIR>  Output directory for the merged results [default: output]
  -h, --help                     Print help (see more with '--help')
```

`--help` adds a paragraph to some options, describes each possible value and lists the exit
statuses. `tests/cli_help.rs` fails when the two blocks above no longer match the binary.

## Artifact Kinds and Plans

Before downloading a Shard, the program picks its Plan: the cheapest Formats, among those the
Shard's Dataset publishes, that serve every requested kind not yet done for it. Each kind then reads
the cheapest of its own accepted Formats inside the Plan:

| `--extract` | Plan on CC-MAIN | Downloaded per Shard |
|-------------|-----------------|----------------------|
| `onion,favicon` (default) | WAT + WET: `onion` reads both, `favicon` WAT | ~240 MB |
| `favicon` | WAT | ~170 MB |
| `onion` | WAT + WET | ~240 MB |
| anything with `inline-favicon` | WARC: every kind reads it | ~1 GB |

CC-NEWS is taken to publish WARC only (not yet verified), so its Plan is always WARC.
`--formats` forces the Formats
downloaded; it is rejected if they can't serve a requested kind
(`cannot extract favicon from wet: it needs warc or wat`). WARC and WAT + WET find the same
Artifacts on most pages, not all: see [`FEATURES.md`](documentation/FEATURES.md#known-limitations).

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

Key optimizations: the custom record parser skips the bodies of records no kind reads (~60%
of a WARC), SIMD literal search replaces the regex engine, `zlib-ng` backend for faster gzip
decompression.

The `memory` Transport holds every Archive of a Shard's Plan in RAM (~240 MB for WAT + WET,
~1 GB for WARC) × concurrent jobs. Layered resource guards automatically cap concurrency:
jobs are limited to 2× CPU cores, and with `--transport memory`, further limited by available
RAM (queried on macOS and Linux) divided by the largest estimated Plan among the scheduled
Shards, to prevent OOM.

## Output Format

Each Artifact kind has its own file: `output/onions.json`, `output/favicons.json` and
`output/inline_favicons.json`; a run only loads and saves the kinds it extracts. In the first
two, each Artifact (a `.onion` address, a favicon URL) maps to a list of Sightings: the
clearnet page where it was found, the crawl date, and the Shard (the Archive file name
without its Format suffix, such as `.warc.gz`):

```json
{
  "exampleexampleexampleexampleexampleexampleexampleexample.onion": [
    {
      "page_url": "https://example.com/page",
      "date": "2025-01-01T00:00:01Z",
      "shard": "CC-MAIN-20250101000000-20250101010101-00000"
    }
  ]
}
```

`inline_favicons.json` maps the SHA-256 of each image to its Shodan favicon hash (`mmh3`,
the number `http.favicon.hash:` takes), its media type, the image itself in base64, and its
Sightings:

```json
{
  "49e1dad481e94dfab7c9573a9a81d56aa2ca629fe15a3f7a910aa4f47601c00d": {
    "mmh3": 1932519735,
    "media_type": "image/png",
    "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ...",
    "sightings": [{ "page_url": "...", "date": "...", "shard": "..." }]
  }
}
```

Sighting metadata is extracted from WARC headers (`WARC-Target-URI`, `WARC-Date`) during
parsing; in WAT, whose own `WARC-Date` is when the WAT was generated, the crawl date is
read from the JSON (`Envelope.WARC-Header-Metadata.WARC-Date`). Results are deduplicated
on `(page_url, shard)` pairs. Files written before this shape (with `url` / `archive`
fields) are not converted: a run that finds one in its output directory stops with an
error instead of overwriting it.

`output/processed.log` records which (Shard, Artifact kind) pairs are done, one
`<shard> <kind>` line each, such as `CC-MAIN-20250101000000-20250101010101-00000 onion`. A
run only extracts the requested kinds not yet done for a Shard, and a pair is recorded only
after its results file is saved. Lines written before kinds were tracked (bare Archive file
names) are ignored, so those Shards are processed again.

## Running on a Cluster

One process runs on one machine, so a Crawl spread over a cluster is split: each process
takes a slice of the paths file (`--offset`, `--limit`) and writes to its own
`--output-dir`, so no two processes write the same file. `cc-extract merge <DIR>...`
then combines their results files, deduplicated as above (`processed.log` files are not
merged). [`examples/slurm/crawl.sh`](examples/slurm/crawl.sh) runs this as a SLURM array job,
several processes per node, and [`examples/slurm/merge.sh`](examples/slurm/merge.sh) merges
the results once it has finished; replace their `<...>` placeholders first.
