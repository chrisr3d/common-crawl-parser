# cc-extract

A Rust program that extracts Artifacts, such as `.onion` addresses and favicons, from [Common Crawl](https://commoncrawl.org/) archives.

This project is also a **hands-on Rust tutorial** — each step introduces new language concepts with well-commented code and a learning journal (`PROGRESS.md`) explaining the reasoning behind every pattern used.

## Purpose

Common Crawl publishes petabytes of crawled web pages. Each Shard of a Crawl (one file-level part of it) comes in up to three Formats: WARC (raw HTTP responses, ~1 GB), WAT (JSON metadata extracted from them, ~170 MB) and WET (their plain text, ~70 MB). This tool downloads, for each Shard, the cheapest Formats that hold what was asked for, parses them, and extracts the requested Artifact kinds:

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
5. **Favicon extraction** — Find the favicons HTML pages declare, resolved against the page's `<base href>`; inline images are recorded by their SHA-256, with their SHA-1, MD5 and Shodan's `mmh3` favicon hash, and saved to disk on request (`--save-images`)
6. **Deduplication & results store** — Deduplicate Sightings and write them, Shard by Shard, to a kvrocks store, over a Unix socket or TCP
7. **Concurrent processing** — Download and parse several Shards in parallel with async/tokio
8. **Ripgrep-style parsing** — Transport (`-t`) and onion search engine (`--onion-engine`) selectable at runtime
9. **Sighting metadata** — Record the page URL, crawl date and Shard of each Artifact found
10. **In-memory parsing** — Parse from memory with `--transport memory` to skip disk I/O entirely
11. **Resource guards** — Layered concurrency caps (CPU cores, available RAM, a process's share of it with `--max-memory`) prevent oversubscription and OOM
12. **Incremental extraction** — Pick Artifact kinds with `-e`; a later run adds kinds without redoing the ones already done
13. **Format planning** — Per Shard, download only the cheapest Formats that serve every requested kind (`--formats` to force them): on CC-MAIN, `onion` and `favicon` read WAT + WET (~240 MB) instead of WARC (~1 GB), `favicon` alone WAT only
14. **HPC batch mode** — Split a Crawl across processes with `--offset` and `--limit`, each covering its own Slice of the paths file, all writing to one store; running the same command again retries only what its Slice left undone, and an Archive failing the same way on 3 runs is given up instead of retried forever. Across several nodes, every node writes to one store over TCP (the SLURM example in [`examples/slurm/`](examples/slurm/))

Additional features:

- **CLI with `clap`** — Short flags (`-l`, `-o`, `-j`, `-d`, `-e`, `-t`), auto `--help`, paths file as positional argument
- **Timing** — Per-Shard download/parse duration and averages in summary
- **Crash-safe writes** — Downloads are written under a temporary name and renamed once complete, and a (Shard, kind) pair is marked done only once its Sightings are in the store: a killed run leaves nothing half-written that a run reads, and the next run resumes as is

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

Requires Rust 1.91+ (edition 2024), and a running [kvrocks](https://kvrocks.apache.org/) for
the results (see [Results Store](#results-store)): by default on the Unix socket
`/tmp/kvrocks.sock` (`unixsocket /tmp/kvrocks.sock` in its `kvrocks.conf`). In Docker, on
macOS for instance, a container's socket can't be reached from the host: publish its port
and give the URL instead:

```sh
docker run -d --name kvrocks -p 127.0.0.1:6666:6666 apache/kvrocks
cargo run -- warc.paths --kvrocks redis://127.0.0.1:6666
```

```sh
cargo build                                    # compile (debug)
cargo build --release                          # compile (optimized — ~5.6s per 864MB archive)
cargo run -- warc.paths                        # download & parse every Shard
cargo run -- warc.paths.gz                     # same, from gzipped paths file
cargo run -- warc.paths -l 3                   # process the first 3 paths only
cargo run -- warc.paths -j 2                   # 2 concurrent Shards (default: CPU cores)
cargo run -- warc.paths -d                     # delete each Shard's Archives after parsing
cargo run -- warc.paths -e onion               # extract onions only (default: onion,favicon)
cargo run -- warc.paths -e onion,favicon       # later: adds favicons, skips the onion work done
cargo run -- warc.paths -e onion,inline-favicon  # inline favicons need WARC; onions read it too
cargo run -- warc.paths -e inline-favicon --save-images images  # also write each image to images/
cargo run -- wat.paths.gz                      # any Format's paths file: Shards are the same
cargo run -- warc.paths --formats warc         # force the Formats downloaded per Shard
cargo run -- warc.paths -t disk                # parse from the downloaded file (default)
cargo run -- warc.paths -t memory              # parse from memory (no disk I/O)
cargo run -- warc.paths -t memory --max-memory 12  # ... holding at most 12 GB of Archives
cargo run -- warc.paths -t mmap                # decompress + mmap (needs disk space)
cargo run -- warc.paths --onion-engine regex   # regex::bytes instead of memchr (default)
cargo run -- warc.paths.gz -l 3 -j 2 -d        # combined (short flags)
cargo run -- warc.paths.gz -l 3 -j 2 -t memory -e onion  # combined with in-memory parsing
cargo run -- warc.paths --limit 3 --jobs 2 --delete --transport disk  # combined (long flags)
cargo run -- warc.paths -o 1000 -l 1000        # one Slice of a Crawl: paths 1001 to 2000
cargo run -- warc.paths --kvrocks run/kvrocks.sock       # the store on another socket
cargo run -- warc.paths --kvrocks redis://127.0.0.1:6666  # the store over TCP
CC_EXTRACT_KVROCKS_PASSWORD=secret cargo run -- warc.paths  # a store (namespace) with a password
cargo run -- --help                            # show usage and all options
cargo run --release --example baseline -- download/X.warc.gz  # original parser, as a benchmark
```

## Usage

`cc-extract -h` prints:

```text
Extract artifacts, such as .onion addresses and favicon URLs, from Common Crawl archives

Usage: cc-extract [OPTIONS] <INPUT>

Arguments:
  <INPUT>  Path to a WARC, WAT or WET paths file (supports .gz)

Options:
  -l, --limit <LIMIT>                Number of paths to process after --offset, the Slice (default: all the rest)
  -o, --offset <OFFSET>              Skip the first N paths in the file (for SLURM array partitioning) [default: 0]
  -j, --jobs <JOBS>                  Number of concurrent download+parse tasks (default: number of CPU cores)
  -d, --delete                       Delete each Shard's Archives once parsed
  -e, --extract <EXTRACT>            Artifact kinds to extract, comma-separated [default: onion,favicon] [possible values: onion, favicon, inline-favicon]
      --formats <FORMATS>            Formats to download for every Shard, comma-separated (default: the cheapest ones serving every kind) [possible values: warc, wat, wet]
  -t, --transport <TRANSPORT>        How downloaded Archives reach the parser [default: disk] [possible values: disk, memory, mmap]
      --max-memory <GB>              Most RAM this process's in-memory downloads may hold, in GB of 2^30 bytes (default: the available RAM)
      --onion-engine <ONION_ENGINE>  Search used to find .onion addresses [default: memchr] [possible values: memchr, regex]
      --kvrocks <SOCKET|URL>         kvrocks store receiving results and done marks: a Unix socket path, or a redis://host:port URL [default: /tmp/kvrocks.sock]
      --save-images <DIR>            Save each inline favicon image as DIR/<first 2 hex digits of its SHA-256>/<SHA-256>
  -h, --help                         Print help (see more with '--help')
```

`--help` adds a paragraph to some options, describes each possible value and lists the exit
statuses. `tests/cli_help.rs` fails when the block above no longer matches the binary.

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

CC-NEWS publishes WARC only, so its Plan is always WARC.
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
RAM (queried on macOS and Linux), or `--max-memory` GB if lower, divided by the largest
estimated Plan among the scheduled Shards, to prevent OOM. Processes sharing a machine each
see all of its available RAM: `--max-memory` gives each one its share.

## Results Store

Results go to a kvrocks store (the Redis protocol, kept on disk), written after each Shard;
no results file is written. Each Sighting is one Page in an Artifact's set: the clearnet page
where it was found, the crawl date, and the Shard (the Archive file name without its Format
suffix, such as `.warc.gz`). Kinds are named as on the command line:

| Key | Type | Content |
|---|---|---|
| `page:<id>` | hash | `page_url`, `date`, `shard` of one Page |
| `<kind>:<artifact>` | set | ids of the Pages the Artifact was seen on |
| `page:<id>:<kind>` | set | the Page's Artifacts of that kind |
| `artifacts:<kind>` | set | every Artifact of the kind |
| `image:<sha256>` | hash | an inline favicon's `media_type`, Shodan favicon hash (`mmh3`, the number `http.favicon.hash:` takes), `sha1` and `md5` |
| `mmh3:<value>`, `sha1:<hex>`, `md5:<hex>` | set | SHA-256s of the inline favicons with that hash |
| `processed` | set | `<shard> <kind>`, one per done (Shard, kind) pair |
| `failures` | set | `<archive> <run>`, one per failure counted on an Archive (its file name) |
| `failures:<archive>` | hash | the error message of each run that counted a failure on the Archive |

An `<artifact>` is a `.onion` address, a favicon URL, or the SHA-256 of an inline favicon (the
store keeps no image bytes: `--save-images <dir>` writes each image to
`<dir>/<first two hex digits of its SHA-256>/<SHA-256>`). A Page's `<id>` is the first 16
bytes of the SHA-256 of `"<shard> <page_url>"`, in hex. For instance:

```sh
redis-cli -s /tmp/kvrocks.sock SMEMBERS artifacts:onion       # every onion found
redis-cli -s /tmp/kvrocks.sock SMEMBERS onion:<address>       # the Pages it was seen on
redis-cli -s /tmp/kvrocks.sock HGETALL page:<id>              # one Page
redis-cli -s /tmp/kvrocks.sock SMEMBERS mmh3:<value>          # the images with a Shodan hash
```

Sighting metadata is extracted from WARC headers (`WARC-Target-URI`, `WARC-Date`) during
parsing; in WAT, whose own `WARC-Date` is when the WAT was generated, the crawl date is
read from the JSON (`Envelope.WARC-Header-Metadata.WARC-Date`). Results are deduplicated
on `(page_url, shard)` pairs, and every write only adds (`SADD`, `HSETNX`): the first date
or media type written is kept.

A run only extracts the requested kinds not yet done for a Shard, and a pair joins
`processed` only once all its Sightings are in the store: a run killed in between does
the pair again, which changes nothing. A store that can't be reached stops the run before
anything is downloaded. If the store needs a password, it is read from
`CC_EXTRACT_KVROCKS_PASSWORD`, never from an option.

A failure that comes back on every run (a download answered 404, an Archive whose bytes don't
decode) is counted against its Archive, once per run. After 3 runs the Archive is given up: the
kinds reading it are not scheduled again, the summary lists it with its last error, and a run
with nothing else left to retry exits with 4. `--formats` can plan around it (a given-up WET:
`--formats warc`). To retry it, delete its record (and an Archive corrupt in `download/`, so it
is downloaded again):

```sh
redis-cli -s /tmp/kvrocks.sock DEL failures:<archive file name>   # retry one Archive
redis-cli -s /tmp/kvrocks.sock DEL failures                       # retry every one
```

More in [`documentation/FEATURES.md`](documentation/FEATURES.md), section 9.

## Running on a Cluster

Each process takes a Slice of the paths file (`--offset`, `--limit`): running the same command
again covers the same paths, so a process re-run after exit 3 retries only its own undone
pairs. Several processes on one machine can write to the same store: each writes its own
Shards, and writes only add; with `--transport memory`, give each one its share of the RAM
with `--max-memory`.
Across several nodes, every process writes to one store over TCP (`--kvrocks
redis://host:port`): run it outside the job, on a host every compute node can connect to, on
a trusted network (the traffic is not encrypted). Re-runs on any node resume from it. One
server's write rate bounds the whole Crawl (about 1.5 s per Shard for one writer; see
FEATURES, section 10). [`examples/slurm/crawl.sh`](examples/slurm/crawl.sh) is a SLURM
array job running several processes per node this way.
