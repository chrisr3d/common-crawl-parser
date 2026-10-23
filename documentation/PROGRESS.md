# Progress Journal

## Step 1: Project Scaffolding — Read WARC Paths File

### What we built

A minimal Rust binary that reads a file of WARC archive paths (one per line) and prints
each path with its line number. Accepts any path file as a CLI argument, defaulting to
`warc.paths`. This is the foundation that all subsequent steps build on.

### Rust concepts introduced

**`std::env::args()` — CLI argument parsing**
Returns an iterator over the command-line arguments passed to the program. Index 0 is
the program name, index 1 is the first user argument. We use `.nth(1)` to grab it as
an `Option<String>`, then `unwrap_or_else` to provide a default value.

**`Result<T, E>` — Error handling without exceptions**
Rust has no exceptions. Functions that can fail return `Result`, which is either `Ok(value)`
or `Err(error)`. `File::open` returns `Result<File, io::Error>`. We handle the error case
explicitly with `unwrap_or_else`, printing to stderr and exiting with a non-zero code.

**`BufReader` — Buffered I/O**
Reading a file byte-by-byte (or line-by-line without buffering) triggers a system call per
read. `BufReader` wraps a `File` with an 8 KB in-memory buffer, so the OS reads in large
chunks and our code consumes from the buffer. Same result, far fewer syscalls.

**`.lines().enumerate()` — Iterator composition**
`.lines()` on a `BufReader` returns an iterator that lazily yields one `Result<String>` per
line. `.enumerate()` wraps each item as `(index, value)`. No vector is allocated — lines
are processed one at a time (this is what Rust calls a "zero-cost abstraction").

**`match` — Pattern matching**
Rust's `match` is an exhaustive pattern-matching expression. The compiler ensures every
variant is handled. We match on `Ok(line)` and `Err(err)` to process good lines and
report bad ones without crashing.

**`println!` vs `eprintln!` — stdout vs stderr**
`println!` writes to stdout (the data stream). `eprintln!` writes to stderr (diagnostics).
This separation matters when piping: `cargo run | head -5` shows only paths, not the
summary line.

**`{:>4}` — Format specifiers**
Rust's formatting mini-language in `println!` supports alignment and width. `{:>4}` means
"right-align in a 4-character field", producing neatly columned output like `   1 | ...`.

### What's next

Step 2: Download WARC archives over HTTP.

---

## Step 2: HTTP Download of WARC Archives

### What we built

An HTTP downloader that fetches Common Crawl WARC archives to a local `download/` directory.
Each URI from `warc.paths` is prepended with `https://data.commoncrawl.org/` to form the
full URL. Archives are streamed to disk (never fully loaded into memory), already-downloaded
files are skipped, and a `--limit N` flag caps how many files to fetch per run.

### Rust concepts introduced

**External crates (`Cargo.toml` dependencies)**
Rust's package manager Cargo resolves dependencies declared in `Cargo.toml`. Adding
`ureq = "3"` pulls the `ureq` HTTP client and all its transitive dependencies. We chose
`ureq` over `reqwest` because it's blocking-only with minimal dependencies — no hidden
async runtime. This keeps the code simple while we learn fundamentals.

**`Box<dyn Error>` — trait objects for error handling**
`Box<dyn Error>` is a heap-allocated pointer to *any* type implementing the `Error` trait.
This lets a function return different error types (io::Error, ureq::Error, etc.) through
a single return type. The caller doesn't need to know the concrete type — it can still
print the error message via the `Display` trait.

**The `?` operator — early return on error**
`?` is syntactic sugar for: "if this Result is Err, return the error from the current
function; otherwise, unwrap the Ok value." It replaces verbose `match` blocks and makes
error propagation concise. It also automatically converts error types when the function
returns `Box<dyn Error>`.

**`Path` / `PathBuf` — cross-platform file paths**
`Path` is a borrowed path slice (like `&str`), `PathBuf` is the owned version (like
`String`). `.join()` appends path components with the correct OS separator. Unlike raw
strings, these types handle platform differences (e.g., `/` vs `\`) correctly.

**`fs::create_dir_all` — idempotent directory creation**
Like `mkdir -p` in Unix: creates the directory and all parents if needed, silently
succeeds if the directory already exists. Idempotent operations like this are great for
robustness — the program works whether it's the first run or the hundredth.

**`File::create` vs `File::open`**
`File::open` opens a file for reading. `File::create` opens for writing, creating the
file if it doesn't exist or truncating it if it does. Two separate functions make the
intent explicit at the call site.

**`impl Trait` in function parameters**
`fn download_with_progress(reader: impl Read, writer: impl Write, ...)` accepts *any*
type implementing `Read` or `Write`. This is compile-time polymorphism — the compiler
generates specialized code for each concrete type used. It's Rust's equivalent of
generics with trait bounds, written in a more readable form.

**`Read` / `Write` traits — streaming I/O**
The `Read` trait provides `.read(&mut buf)` for pulling bytes from a source. The `Write`
trait provides `.write_all(&buf)` for pushing bytes to a destination. By programming
against traits (not concrete types), our download function works with files, network
streams, or in-memory buffers.

**`.take(n)` on iterators — lazy limiting**
`.take(n)` wraps an iterator so it yields at most `n` items, then stops. It's lazy —
it doesn't collect or allocate, just stops pulling from the inner iterator. We use it
to cap downloads: `.lines().filter(...).take(limit)`.

**`str::parse::<T>()` — parsing strings into typed values**
The turbofish syntax `::<usize>` tells the compiler what type to parse into. `.parse()`
returns `Result<T, ParseError>`, so invalid input is caught at runtime without panicking.

**Borrow checker and temporary lifetimes**
When chaining method calls like `.into_body().with_config().reader()`, each intermediate
value must live long enough for the next call to borrow from it. We split the chain into
separate `let` bindings so the borrow checker can verify that each reference is valid.
This is a common Rust pattern — explicit bindings make lifetimes clear.

### What's next

Step 3: Decompress the downloaded `.warc.gz` files and parse WARC records to extract
their content for further processing.

---

## Steps 3–5: WARC Parsing, .onion Extraction, and Deduplication

### What we built

A complete processing pipeline that decompresses WARC archives, scans for `.onion`
addresses using regex, deduplicates results, and persists them to JSON. The program now
implements a three-state model for each archive:

1. **Already processed** (in `output/processed.log`) → skip entirely
2. **Downloaded but not parsed** (file exists in `download/`) → parse it
3. **Not downloaded** → download first, then parse

Results are stored in `output/onions.json` as a map from each `.onion` address to the
list of archives it was found in. A `--delete` flag optionally removes archives after
parsing to save disk space.

### Rust concepts introduced

**`HashMap<K, V>` — key-value hash table**
Rust's standard hash map provides O(1) average-case lookup and insertion. We use
`HashMap<String, Vec<String>>` to map each `.onion` address to its source archives.
The `entry().or_default()` pattern is the idiomatic way to do "get-or-insert" — it
avoids a double lookup (one to check existence, one to insert).

**`HashSet<T>` — unique membership collection**
`HashSet` stores unique values with O(1) average-case lookup via hashing. We use it
in two places: to track already-processed filenames (skip-if-processed logic), and for
per-archive deduplication of `.onion` addresses during parsing.

**The `warc` crate — structured WARC parsing**
Instead of raw byte scanning with `flate2` + `read_until`, we use the `warc` crate
which understands the WARC archive format. `WarcReader::from_path_gzip` handles gzip
decompression internally and parses record boundaries, headers, and bodies. Each record
is yielded as a typed struct with a `warc_type()` (Response, Request, Metadata, etc.)
and a `body()` payload. By filtering to only `RecordType::Response`, we skip binary
content, request records, and metadata — processing ~30–50% of the data instead of 100%.

**`RecordType` enum — WARC record types**
WARC records are typed: Response (HTTP response bodies), Request (HTTP requests),
Metadata, WarcInfo, etc. Only Response records contain the HTML/JS content where
`.onion` links appear. Pattern matching on the enum lets us skip everything else.

**Why structured parsing beats raw scanning**
The previous approach decompressed every byte and scanned it through regex — including
binary content (images, fonts) that produced multi-megabyte "lines" with no newlines.
Working at the right abstraction level (WARC records instead of raw bytes) is a general
performance lesson: when data has structure, use it.

**`Regex` compilation and `find_iter` — pattern matching**
`Regex::new()` compiles a pattern string into an efficient automaton. This compilation
is expensive, so we do it once outside the loop. `find_iter()` returns an iterator of
all non-overlapping matches in a string, which we use to scan each line for `.onion`
patterns. Our regex matches both v2 (16-char) and v3 (56-char) onion addresses using
base32 character classes.

**`serde_json` — JSON serialization without derive macros**
`serde_json::to_string_pretty` serializes any type that implements serde's `Serialize`
trait. Standard library types like `HashMap`, `Vec`, and `String` get this automatically
through blanket implementations — no `#[derive(Serialize)]` needed.

**`OpenOptions` — fine-grained file opening**
Unlike `File::create` (which truncates) or `File::open` (read-only), `OpenOptions`
lets us combine flags: `.append(true)` positions writes at the end (like `>>` in shell),
`.create(true)` creates the file if it doesn't exist. We use this for the processed log
so we never lose previously logged entries.

**`Cow<str>` via `String::from_utf8_lossy` — zero-cost when possible**
`from_utf8_lossy` returns `Cow<str>` (Copy-on-Write). If the input bytes are valid
UTF-8 (the common case), it borrows the original data with no allocation. If bytes
contain invalid sequences, it allocates a new String with U+FFFD replacement characters.
We use this to convert WARC response bodies (which are `&[u8]`) to strings for regex
scanning.

### Correctness fixes applied later

**Duplicate archive names in results** — The original `results.entry(onion).or_default().push()`
blindly appended the archive filename. If an archive was reprocessed (interrupted run, manual
re-run), the same filename would appear multiple times. Fixed with `Vec::contains` before
inserting. We chose `Vec::contains` (linear scan) over `HashSet` because the lists are tiny
(1–5 entries per onion) — for small N, a linear scan beats the hashing overhead, and `Vec`
preserves insertion order for stable JSON output.

**Incremental result persistence** — Originally, `save_results` ran once after the loop while
`mark_processed` ran per-archive. A crash between the two could cause results and processed
state to diverge. Now both run per-archive: if either fails, the next run reprocesses that
archive (safe, just redundant). The final `save_results` after the loop remains as a safety
net. This "save after each unit of work" pattern is standard for batch jobs where interruption
is expected.

### What's next

Performance optimization: benchmark and fix regex performance, optimize debug builds.

---

## Performance Fixes

### Root cause: catastrophic regex performance with `(?i)` flag

The crawler was taking ~2.5 minutes (release) to parse a 1GB WARC archive, while the
old crawler did it in ~17 seconds. Isolating the bottleneck via a minimal benchmark
revealed that WARC parsing + gzip decompression takes only ~15s — the entire slowdown
was in the regex.

The original regex `(?i)\b[a-z2-7]{16}\.onion\b|\b[a-z2-7]{56}\.onion\b` used the
case-insensitive `(?i)` flag. When combined with `\b` (word boundary assertions), this
forces the `regex` crate off its fast DFA (deterministic finite automaton) path into a
much slower execution mode. The engine can no longer use literal prefix optimizations
(scanning for `.onion` as a fixed string) and must evaluate the full automaton at every
byte position across 4.5GB of decompressed text.

The fix was switching to the old crawler's pattern: `\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b`
(case-sensitive). Since `.onion` addresses are base32 and conventionally lowercase, and
our code already calls `.to_lowercase()` on matches, case-insensitive matching was
unnecessary. This regex is **1,250x faster** on the same data.

| Regex | Time (4.5GB text, release) |
|---|---|
| `(?i)\b[a-z2-7]{16}\.onion\b\|\b[a-z2-7]{56}\.onion\b` | 125.6s |
| `\b([a-z2-7]{16}\|[a-z2-7]{56})\.onion\b` | 0.1s |

**Lesson: regex performance is not intuitive.** Small flag changes (`(?i)`) can cause
orders-of-magnitude slowdowns depending on how the regex engine optimizes internally.
When performance matters, benchmark the actual regex against real data. The `regex` crate
has excellent documentation on its optimization strategies in the
[`regex` crate docs](https://docs.rs/regex/latest/regex/#performance).

### Optimized dependency compilation in debug mode

Even with the fast regex, debug builds are slower because dependency code (gzip
decompression, regex automaton, WARC parsing) runs without optimization. The standard
Rust fix is to optimize dependencies at `-O2` while keeping our own code in debug mode:

```toml
[profile.dev.package."*"]
opt-level = 2
```

**`[profile.dev.package."*"]` — per-package profile overrides**
Cargo allows overriding compiler optimization levels on a per-package basis within a
profile. `dev` is the profile used by `cargo build` and `cargo run`. `package."*"` is a
wildcard matching all dependency crates (but not our own crate). `opt-level = 2` is the
same optimization level used by the `release` profile. This gives us the best of both
worlds: fast dependency code + debuggable application code.

Final measured results on a 1GB WARC archive (~30,000 records, ~15,000 responses):
- **Release build**: ~16s (matching old crawler's ~17s)
- **Debug build with `opt-level = 2` on deps**: ~1m 20s
- **Debug build without optimization**: would be significantly slower

### What's next

Step 6: Concurrent downloads and processing with async/tokio.

---

## Step 6: Concurrent Downloads & Processing with Tokio

### What we built

A concurrent processing pipeline that downloads and parses multiple WARC archives in
parallel. The sequential bottleneck (download 1 → parse 1 → download 2 → parse 2) is
replaced with a pipeline where up to N archives download simultaneously, and parsing
starts immediately when each download completes. A `--jobs N` flag controls the
concurrency level and `--limit N` caps the number of archives to process.

Key architectural changes:
- Replaced `ureq` (blocking HTTP) with `reqwest` (async HTTP with Tokio)
- `main` is now `async fn main()` driven by the Tokio multi-threaded runtime
- Downloads use async I/O — threads are released during network waits
- WARC parsing (CPU-bound) runs on Tokio's blocking thread pool via `spawn_blocking`
- `futures::stream::buffer_unordered` provides bounded concurrency
- `Arc<Regex>` shares the compiled regex across concurrent tasks

### Rust concepts introduced

**`async`/`await` — cooperative multitasking**
Async functions return `Future`s — values that represent incomplete computation. When
you `.await` a future, the current task *suspends* and yields control back to the
runtime, which can then run other tasks on the same thread. This is cooperative
multitasking: tasks voluntarily give up the thread at `.await` points, unlike OS threads
where the scheduler preempts them. The key benefit: thousands of concurrent I/O operations
can share just a few OS threads, because most are waiting for network/disk, not using CPU.

**Tokio runtime — the async executor**
Async code doesn't run by itself — it needs an *executor* to poll futures to completion.
`#[tokio::main]` sets up a multi-threaded Tokio runtime (one worker thread per CPU core
by default) and drives our `async fn main()` on it. The runtime manages task scheduling,
I/O event notification (via `epoll`/`kqueue`), and timer events. It's the engine that
makes `.await` actually work.

**`spawn_blocking` — bridging sync and async worlds**
Not everything can (or should) be async. The `warc` crate is synchronous and does
CPU-heavy work (gzip decompression + parsing). Running this directly on an async worker
thread would block it, starving other async tasks. `tokio::task::spawn_blocking` moves
the work to a separate thread pool designed for blocking operations. The async task
suspends at `.await` until the blocking work completes, keeping the async threads free.
Rule of thumb: if a function does CPU work or blocking I/O for more than a few
microseconds, use `spawn_blocking`.

**`reqwest` — async HTTP streaming**
`reqwest` is Tokio-native: its `.send().await` releases the thread during the entire
HTTP request/response cycle. The response body is consumed chunk-by-chunk with
`.chunk().await`, where each `.await` releases the thread during network waits. Compare
with `ureq` where the thread sits blocked during the entire transfer. For concurrent
downloads, async means 4 downloads sharing 1 thread vs. 4 downloads needing 4 blocked
threads.

**`buffer_unordered(N)` — bounded concurrent stream processing**
`futures::stream::buffer_unordered(N)` is a stream combinator that polls up to N futures
simultaneously, yielding results as each completes (not in submission order). When one
finishes, the next pending future starts. This gives us bounded concurrency without
manual semaphore management. "Unordered" is key: a fast download isn't held up waiting
for a slow one just because the slow one started first.

**`Arc<T>` — atomic reference counting for shared ownership**
Each concurrent task needs access to the compiled regex and HTTP client. Normal references
(`&Regex`) won't work because Tokio tasks require `'static` lifetimes (they could outlive
the spawning scope). `Arc` (Atomic Reference Count) wraps a value in a thread-safe smart
pointer: `Arc::clone()` is cheap (just increments an atomic counter), and the inner value
is dropped when the last `Arc` goes away. `Arc` provides shared *immutable* access — for
shared mutable state you'd combine it with a `Mutex` (`Arc<Mutex<T>>`), but we avoid that
by merging results sequentially on the main task.

**`pin_mut!` — pinning streams for polling**
Async streams must be "pinned" (guaranteed not to move in memory) before they can be
polled. `futures::pin_mut!` pins a value to the stack. This is a detail of Rust's async
model: because futures are state machines that contain self-references, moving them after
creation would invalidate those references. Pinning is the compiler's guarantee that this
won't happen.

**Concurrent work, sequential merging**
The pipeline is concurrent for downloads and parsing, but result merging (updating the
HashMap, writing files) is sequential on the main task. This avoids locks and race
conditions entirely — the simplest correct approach. This is a common async pattern:
fan out for independent work, fan in for shared state updates.

### Dependencies changed

- **Removed `ureq`**: blocking HTTP client, replaced by async `reqwest`
- **Added `reqwest`**: async HTTP client native to Tokio, with streaming body support
- **Added `tokio`**: the async runtime (multi-threaded executor, async I/O, timers,
  blocking thread pool). Features: `rt-multi-thread`, `macros`, `fs`, `sync`
- **Added `futures`**: stream utilities (`StreamExt`, `pin_mut!`, `buffer_unordered`)
  that complement Tokio's core functionality

---

## Additional Improvements

### Smarter defaults for `--jobs` and `--limit`

**Auto-detect CPU cores for `--jobs`** — The initial default of 4 concurrent jobs was
an arbitrary constant. Replaced with `std::thread::available_parallelism()`, which
queries the OS for the number of logical CPUs (hardware threads). The program now
scales to the machine it runs on: a 16-core server uses 16 jobs, a 4-core laptop
uses 4. Falls back to 1 if detection fails (e.g. constrained containers).

**`std::thread::available_parallelism()` — runtime hardware detection**
Returns `Result<NonZeroUsize>` — a safe, non-panicking query with no side effects.
It's the standard library's replacement for the `num_cpus` crate (stable since Rust
1.59). `NonZeroUsize` guarantees the value is at least 1, and `.get()` converts it
to a plain `usize`.

**Remove processing limit** — The initial default of `--limit 1` meant the program
only processed one archive per run unless explicitly overridden. Changed to unlimited
by default (internally `limit = 0`, with the limit check guarded by `limit > 0`).
The program now processes all unprocessed URIs in the paths file, which is the
expected behavior for a batch processing tool. `--limit N` remains available for
testing or resource-constrained runs.

### Per-archive timing instrumentation

Added wall-clock timing for each archive's download and parse phases using
`std::time::Instant`. Each archive now reports its download time and parse time
individually. The final summary includes average download and parse times across
all processed archives, giving visibility into where time is spent.

**`std::time::Instant` — monotonic clock for benchmarking**
`Instant::now()` captures a point in time. `start.elapsed()` returns a `Duration`
representing the wall-clock time since that instant. Unlike system clocks,
`Instant` is monotonic — it never goes backwards (e.g. due to NTP adjustments),
making it safe for measuring elapsed time. `Duration::as_secs_f64()` converts
to a floating-point seconds value for display.

### Portable TLS with `rustls`

The default `reqwest` configuration uses OpenSSL for TLS, which requires system
packages (`libssl-dev`, `pkg-config`) that may not be present on minimal Linux
installations or Docker images. Switched to `rustls` — a pure-Rust TLS implementation:

```toml
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }
```

This eliminates the system dependency entirely. The binary compiles on any platform
with just the Rust toolchain, consistent with the project's portability goal.

---

## Post-1.0.0: CLI, Gzip Paths, and Code Structure

### `clap` derive for CLI argument parsing

Replaced the hand-rolled `while` loop argument parser (~50 lines of repetitive
`strip_prefix` / `==` checks) with `clap`'s derive macro. The entire CLI definition
is now a struct with attributes:

```rust
#[derive(Parser)]
#[command(name = "onion-crawler")]
#[command(about = "Extract .onion addresses from Common Crawl WARC archives")]
struct Config {
    /// Path to the WARC-paths file (supports .gz)
    input: String,

    /// Maximum number of archives to process (default: all)
    #[arg(short, long)]
    limit: Option<usize>,

    /// Number of concurrent download+parse tasks
    #[arg(short, long, default_value_t = default_jobs())]
    jobs: usize,

    /// Delete archive files after parsing
    #[arg(short, long)]
    delete: bool,
}
```

### Rust concepts introduced

**`clap` derive macro — declarative CLI definitions**
`#[derive(Parser)]` generates all argument parsing code from the struct definition.
Each field becomes a CLI argument: positional fields (no `#[arg]` with `short`/`long`)
are positional arguments, fields with `#[arg(short, long)]` become flags. `clap`
handles `--flag value`, `--flag=value`, `-f value`, type parsing, error messages,
and `--help` generation automatically.

**`///` doc comments as help text**
`clap` turns doc comments (`///`) on struct fields into the `--help` descriptions.
This is why the struct-level explanation uses regular comments (`//`) instead —
otherwise `clap` would include those in the help banner too. The `#[command(about)]`
attribute explicitly sets the one-line program description shown in `--help`.

**`Option<usize>` for optional arguments**
`limit` is `Option<usize>` instead of the previous `usize` with 0-means-unlimited.
`Option` is Rust's way of expressing "this value may or may not be present" — it's
either `Some(value)` or `None`. This is more expressive than sentinel values (0, -1)
because the type itself encodes the possibility of absence.

**`if let Some(x)` — pattern matching on `Option`**
To check and extract an `Option` value in one step:
```rust
if let Some(limit) = config.limit {
    if work_items.len() >= limit { break; }
}
```
`if let` tries to match the right side against the pattern on the left. If
`config.limit` is `Some(5)`, the pattern matches and `limit` is bound to `5` as
a new local variable scoped to the block. If it's `None`, the block is skipped.
This replaces the previous `if config.limit > 0 && ...` guard. The variable `limit`
doesn't exist before this line — it's created by the pattern match, similar to how
function parameters are created from passed arguments.

**Required positional argument**
The input paths file changed from a hardcoded default (`"warc.paths"`) to a required
positional argument. With `clap`, a `String` field without `default_value` is required —
running the program without it shows a clear error message. This is better for
explicitness: the user always knows which file is being processed.

### Gzip-compressed paths file support

Common Crawl distributes `warc.paths.gz` files. Rather than requiring manual
decompression, the program now detects `.gz` extensions and decompresses transparently:

```rust
let reader: Box<dyn BufRead> = if config.input.ends_with(".gz") {
    let decoder = libflate::gzip::Decoder::new(file)?;
    Box::new(BufReader::new(decoder))
} else {
    Box::new(BufReader::new(file))
};
```

**`Box<dyn BufRead>` — trait objects for runtime polymorphism**
The two branches return different concrete types (`BufReader<Decoder<File>>` vs
`BufReader<File>`), but both implement `BufRead`. `Box<dyn BufRead>` is a trait
object — a heap-allocated pointer to *any* type implementing `BufRead`. This lets
us assign either branch to the same variable. The `dyn` keyword means "dynamic
dispatch": method calls go through a vtable (function pointer table) at runtime,
unlike generic code which is resolved at compile time. The tiny runtime cost is
irrelevant here since we read the paths file once at startup.

**Reusing transitive dependencies**
`libflate` was already compiled as a transitive dependency of the `warc` crate.
Adding `libflate = "1"` to `Cargo.toml` just makes it directly importable — no
new download or compilation needed. This is a practical Rust tip: check `cargo tree`
before adding a new crate — the functionality you need might already be in the
dependency tree.

### Binary + library crate structure

Split the single `main.rs` into two files:
- **`src/main.rs`** — CLI parsing with `clap` and pipeline orchestration (the coordinator)
- **`src/lib.rs`** — all feature code: download, WARC parsing, state management

**Why this structure?**
Rust supports having both a binary (`main.rs`) and a library (`lib.rs`) in the same
package. The binary is the executable entry point; the library holds reusable code.
`main.rs` imports from the library using the crate name: `use onion_crawler::{...}`.
This separation makes the code easier to navigate — the coordinator logic is separate
from the feature implementations — and the library code could be reused by other
binaries or tests.

**`pub` visibility**
Functions and constants in `lib.rs` that `main.rs` needs must be marked `pub` (public).
By default, items in Rust are private to their module. `pub` makes them accessible from
outside the crate. This is Rust's encapsulation: the library controls exactly what it
exposes.

---

## Step 7: Ripgrep-Style Parsing Strategies

### What we built

Four progressively optimized parsing strategies inspired by how ripgrep achieves its
speed, selectable at runtime via `-s` / `--strategy`. Each strategy produces identical
results but uses different techniques, so they can be benchmarked against each other on
the same archive. The default strategy (`memchr`) processes an 864MB archive in ~5.6s
— down from ~16s with the baseline.

| Strategy | Parser | Search | Performance |
|----------|--------|--------|-------------|
| `baseline` | `warc` crate | `regex::Regex` on UTF-8 `String` | ~16s/GB |
| `bytes` | Custom streaming | `regex::bytes::Regex` on `&[u8]` | ~1.5-2x faster |
| `memchr` | Custom streaming | SIMD `memmem` literal search | ~3-5x faster |
| `mmap` | Custom slice (mmap) | SIMD `memmem` + zero-copy bodies | ~3-6x faster |

Two new modules were added:
- **`src/warc_parser.rs`** — Custom byte-level WARC parser (streaming + mmap slice)
- **`src/onion_search.rs`** — Onion extraction strategies (regex-bytes, memchr)

### Rust concepts introduced

**`regex::bytes::Regex` — searching raw bytes without UTF-8 conversion**
The `regex` crate has two modules most people don't know about: `regex::Regex` searches
`&str` (requires valid UTF-8), while `regex::bytes::Regex` searches `&[u8]` (arbitrary
bytes). ripgrep uses `regex::bytes` exclusively because real-world files contain invalid
UTF-8. By searching `&[u8]` directly, the `bytes` strategy eliminates the
`String::from_utf8_lossy()` allocation that the baseline makes for every record body —
instead of converting hundreds of KB per record to a `String`, we search the raw bytes
and only convert the 22-62 byte match.

**`memchr::memmem::Finder` — SIMD-accelerated literal search**
The core technique behind ripgrep's speed. `memmem::Finder::new(b".onion")` compiles a
SIMD-accelerated searcher that scans bytes at 16-32 bytes per CPU cycle (SSE2/AVX2 on
x86_64, NEON on ARM). Instead of running the regex NFA/DFA engine on every byte of every
record body, we jump directly to `.onion` occurrences and validate the surrounding bytes
with cheap comparisons. Since `.onion` is rare in typical web content (0-2 matches per
50-500 KB body), the validator almost never runs.

This is ripgrep's key insight applied: **extract literal substrings from the regex
pattern, use SIMD to find candidates, then validate only those positions.** Our pattern
`\b[a-z2-7]{16,56}\.onion\b` has the fixed literal `.onion`, making it a perfect
candidate for this optimization.

**`#[inline(always)]` — controlling function inlining**
For tiny predicate functions like `is_onion_char(b: u8) -> bool` that are called in hot
loops, `#[inline(always)]` tells the compiler to inline the function body at every call
site. This eliminates function-call overhead (register push/pop, jump) and lets the
compiler optimize the inlined code within the loop context — e.g., keeping the byte value
in a register instead of passing it on the stack. Without the hint, the compiler might
not inline across module boundaries.

**Custom `BufRead`-based WARC parser — selective parsing**
The `warc` crate (v0.4) parses ALL headers with `nom` and allocates a `HashMap` per
record. Our custom `WarcRecordIter` reads headers line-by-line and only extracts
`WARC-Type` and `Content-Length` — everything else is ignored with zero allocation. For
non-response records (request, metadata, warcinfo — ~60% of all records), the body is
skipped entirely by reading and discarding `content_length` bytes through a stack buffer.
This means ~60% of the decompressed data is never read into heap memory.

**`memmap2::Mmap` — memory-mapped file I/O**
Memory mapping makes the OS map a file's contents directly into the process's virtual
address space. Instead of explicit `read()` syscalls, data access happens through page
faults handled by the kernel's virtual memory system. Benefits: zero-copy body slices
(`&[u8]` into the mapped region, no `Vec<u8>` allocation), efficient page cache usage,
and no read syscalls. The trade-off: gzip is a streaming format, so we must decompress
the entire archive to a temporary file first, then mmap that. This costs disk space
(~3-5x the compressed size) but enables the zero-copy parsing.

**`unsafe` blocks — controlled unsafety for `mmap`**
`memmap2::Mmap::map()` requires an `unsafe` block because the OS could theoretically
modify the mapped file while we're reading it (another process could write to it),
causing undefined behavior. We document why our usage is safe: we created the temp file
and no other process modifies it. `unsafe` doesn't mean "dangerous" — it means "the
programmer is responsible for upholding invariants the compiler can't verify." Keeping
`unsafe` blocks small and well-documented is idiomatic Rust.

**`WarcSliceIter` — zero-copy parsing on contiguous slices**
When data is in a contiguous `&[u8]` (from mmap), we can use a different parser that
returns `&[u8]` body slices instead of owned `Vec<u8>`. This is zero-copy: the body
bytes stay in the OS page cache and are never copied to the heap. The slice parser also
uses `memmem` to find `\r\n\r\n` header boundaries (faster than line-by-line reading on
contiguous data). This is only possible when the entire decompressed content is available
at once — the streaming parser can't do this because buffers get reused.

**`flate2` with `zlib-ng` — SIMD-optimized decompression**
The default `flate2` backend is `miniz_oxide` (pure Rust). Switching to `zlib-ng` — a
heavily SIMD-optimized C library for inflate — gave a significant decompression speedup.
Since gzip decompression is the bottleneck for all strategies (not the search), this
benefits every strategy equally:

```toml
flate2 = { version = "1", features = ["zlib-ng"], default-features = false }
```

This links against zlib-ng built from source via `cmake`. It requires a C compiler and
cmake on the build machine, which is a trade-off for portability. The `libflate` crate
is kept for paths-file decompression (small files where performance doesn't matter).

**`clap::ValueEnum` — type-safe enum CLI arguments**
`#[derive(ValueEnum)]` on the `Strategy` enum lets `clap` parse strategy names directly
from the CLI (`--strategy memchr`). The derive macro auto-generates the list of valid
values for `--help` and provides compile-time exhaustive matching in the dispatch code.
Doc comments on enum variants become the help text for each option.

**Manual ASCII digit parsing — avoiding hidden costs**
`Content-Length` values in WARC headers are always ASCII digits. `parse_ascii_usize()`
converts them to `usize` with a direct arithmetic loop instead of `str::parse::<usize>()`.
This avoids: (1) UTF-8 validation (we know it's ASCII), (2) error type construction
(we return 0 for malformed input), (3) generic trait dispatch. For a hot path called
hundreds of thousands of times per archive, these micro-optimizations compound.

### Architecture: why four strategies, not just the fastest?

This is a teaching project. Having all four strategies in the same binary lets you:
1. **Benchmark each optimization in isolation** — run the same archive with `-s baseline`
   then `-s memchr` and compare timing directly
2. **Understand what each technique buys** — the speedup from `baseline` to `bytes` is
   purely about avoiding UTF-8 conversion; from `bytes` to `memchr` is about replacing
   regex with SIMD literals
3. **See the trade-offs** — `mmap` is theoretically fastest but needs 3-5x disk space
   for the temp file and requires `unsafe`; `memchr` is nearly as fast with no downsides

Runtime selection via CLI flag (not cargo features) means you build once and benchmark
all four strategies without recompiling. The binary size cost of including all four is
negligible.

### Dependencies added

- **`memchr`**: SIMD-accelerated byte/substring search — the engine behind ripgrep's
  literal optimization. Provides `memmem::Finder` for searching byte slices.
- **`memmap2`**: Memory-mapped file I/O. Maps files into virtual memory for zero-copy
  access via `&[u8]` slices.
- **`flate2`** (with `zlib-ng`): Gzip decompression wrapping the SIMD-optimized zlib-ng
  C library. Replaces `libflate` for the custom parser's decompression path.

---

## Step 8: WARC Metadata Extraction

### What we built

Rich source context for every `.onion` address found. Previously, each onion mapped to
a list of archive filenames (just "which WARC file"). Now each onion maps to a list of
`OnionSource` structs containing three fields:

- **`url`** — the clearnet page URL where the onion address appeared (from `WARC-Target-URI`)
- **`date`** — when Common Crawl fetched that page (from `WARC-Date`)
- **`archive`** — which WARC archive file contained the record

This answers not just "which archive" but "which specific page, and when was it crawled?"
— much more useful for analysis. The output format changed from flat to nested JSON:

```json
{
  "example1234567890.onion": [
    {
      "url": "https://example.com/links",
      "date": "2024-09-15T12:34:56Z",
      "archive": "CC-NEWS-20240915.warc.gz"
    }
  ]
}
```

Results are deduplicated on `(url, archive)` pairs — the same onion found on the same
page in the same archive is recorded only once.

### Rust concepts introduced

**`#[derive(Serialize, Deserialize)]` — serde derive macros**
The `serde` crate provides Rust's standard serialization framework. Adding
`#[derive(Serialize, Deserialize)]` to a struct auto-generates all the code needed to
convert it to/from any supported format (JSON, TOML, YAML, etc.) at compile time. The
struct field names become the JSON keys directly. This is zero-cost at runtime — the
generated code is as efficient as hand-written serialization. We use `Serialize` in
`save_results()` (struct → JSON) and `Deserialize` in `load_results()` (JSON → struct).

**`serde` — serialize + deserialize framework**
`serde` itself is format-agnostic — it defines the `Serialize` and `Deserialize` traits
that describe how a type converts to/from an abstract data model. The actual format
encoding comes from companion crates like `serde_json`. This separation means the same
`#[derive(Serialize)]` works for JSON, TOML, MessagePack, etc. without changing the
struct. Previously we didn't need derive macros because `HashMap<String, Vec<String>>`
has blanket `Serialize` implementations — but custom structs like `OnionSource` need
the derive.

**Backwards-compatible deserialization with `unwrap_or_default`**
When the output format changes (from `HashMap<String, Vec<String>>` to
`HashMap<String, Vec<OnionSource>>`), old JSON files won't parse into the new type.
Instead of crashing, `load_results()` uses `serde_json::from_str(&content).unwrap_or_default()`,
which falls back to an empty `HashMap` if deserialization fails. This is a practical
pattern for evolving data formats: the first run after the format change reprocesses
archives (since their onions aren't in the new results), and old results are silently
replaced rather than causing errors.

**Extracting WARC headers from the custom parser**
The custom `WarcRecordIter` (streaming) and `WarcSliceIter` (mmap) were extended to
extract `WARC-Target-URI` and `WARC-Date` headers alongside the existing `WARC-Type`
and `Content-Length`. The streaming parser stores them as owned `String` fields in
`WarcRecord`; the slice parser stores them as borrowed `&[u8]` slices in `WarcSlice`
(zero-copy from the mmap region). The baseline strategy reads the same headers from
the `warc` crate via `record.header(warc::WarcHeader::TargetURI)`.

**`Clone` derive for shared references in search functions**
`OnionSource` derives `Clone` because the same source metadata may be referenced
multiple times when a single WARC record body contains multiple distinct onion
addresses. Each match gets its own copy of the source. For small structs (three
`String` fields), cloning is cheap — the alternative (wrapping in `Rc` or `Arc`)
would add complexity for negligible benefit.

### What's next

In-memory streaming mode to eliminate disk I/O from the pipeline.

---

## Step 9: In-Memory Streaming Mode (`--stream`)

### What we built

A `--stream` / `-m` CLI flag that downloads archives into memory instead of to disk,
then parses directly from the in-memory buffer. The entire download/parse pipeline
runs without touching the filesystem — no `download/` directory needed.

The pipeline changes from:
```
HTTP chunks → write to disk → read from disk → decompress → parse
```
to:
```
HTTP chunks → collect in Vec<u8> → decompress from memory → parse
```

Three new functions in `lib.rs`:
- `download_warc_to_memory` — streams HTTP chunks into a `Vec<u8>` instead of a file
- `parse_warc_bytes_from_memory` — `Cursor<Vec<u8>>` → `MultiGzDecoder` → `WarcRecordIter` → regex search
- `parse_warc_memchr_from_memory` — same pipeline with `memmem::Finder` search

Compatible with `bytes` and `memchr` strategies only. Incompatible strategies
(`baseline` — warc crate needs a file path; `mmap` — memory mapping needs a file
descriptor) print a warning and fall back to disk mode automatically.

### Rust concepts introduced

**`std::io::Cursor<T>` — the adapter pattern**
`Cursor` wraps any `AsRef<[u8]>` type (like `Vec<u8>`) and implements `Read` + `Seek`,
making it interchangeable with a `File`. This is trait-based polymorphism in action:
`MultiGzDecoder<R: Read>` doesn't care whether `R` is a `File` or a `Cursor<Vec<u8>>`
— it just calls `.read()`. The same interface, different backing store. This is why
`WarcRecordIter<R: BufRead>` works seamlessly with both — the generic constraint was
already in place from Step 7, so adding in-memory support required zero changes to the
parser.

**Ownership transfer with `move` into `spawn_blocking`**
When we call `spawn_blocking(move || parse_warc_memchr_from_memory(data, &filename))`,
the `data: Vec<u8>` (potentially 800 MB) is *moved* from the async task to the blocking
thread. This is a zero-cost operation — Rust moves the pointer, length, and capacity
(3 machine words), not the 800 MB of data. After the move, the async task no longer
owns the buffer, and the compiler rejects any attempt to use it. This is a concrete
example of why Rust's ownership model exists: the compiler prevents use-after-move at
compile time, which would be a dangling-pointer bug in C/C++.

**`Vec::with_capacity` — pre-allocation**
When `Content-Length` is available from the HTTP response, we pre-allocate the buffer
to the exact size: `Vec::with_capacity(total_size as usize)`. Without this, `Vec`
uses geometric growth — it doubles capacity each time it runs out of space. For an
800 MB download, that means approximately 30 reallocations, each copying all existing
data to a new, larger allocation. Pre-allocating does it in one shot. This is a general
Rust pattern: when you know the approximate size upfront, always use `with_capacity`.

**Graceful degradation — warning + fallback**
When `--stream` is used with an incompatible strategy, we don't error out. Instead,
we print a warning to stderr and fall back to disk mode. This is a good CLI UX pattern:
the user's intent (parse this archive) is still achievable, just via a different path.
The strategy incompatibility is a limitation, not a user error.

**`Option<Vec<u8>>` for conditional data flow**
The pipeline uses `Option<Vec<u8>>` to represent the in-memory buffer: `Some(buffer)`
in stream mode, `None` in disk mode. The `spawn_blocking` closure then matches on
`(strategy, memory_buffer)` — a tuple pattern match that dispatches to the right parse
function based on both the strategy choice and whether we have in-memory data. This
is idiomatic Rust: using the type system to make invalid states unrepresentable.

### Resource Guards (Step 9b)

After adding stream mode, an edge case emerged: running many concurrent stream jobs
could exhaust available RAM (each archive is ~800 MB–1 GB in memory). We added
layered resource guards to cap concurrency safely.

**`std::thread::available_parallelism()` — querying CPU cores**
This returns the number of hardware threads (logical cores) as a `NonZero<usize>`.
We use it both as the default `-j` value and to compute the CPU cap at `2× cores`.
The 2× factor allows N downloads (async, I/O-bound) to overlap with N parses
(CPU-bound in `spawn_blocking`) without oversubscription.

**`#[cfg(target_os = "...")]` — conditional compilation**
Rust's `#[cfg]` attribute controls which code compiles on which platform. Unlike C's
`#ifdef`, this is checked by the compiler, so typos in target names are caught. We
define three `get_available_memory()` implementations — macOS, Linux, and a fallback —
and exactly one compiles into the final binary. The other two don't exist at all.

**`std::process::Command` — safe alternative to FFI (macOS)**
macOS exposes memory info through `sysctl`, a command-line tool that queries kernel
parameters. We spawn it as a subprocess via `Command::new("sysctl").args(["-n", key])`
and parse its stdout. This is slower than a direct C FFI call (~1 ms vs ~1 μs) but
requires no `unsafe` and no C bindings. At startup (one-time cost), this is negligible.
We query page size, free pages, speculative pages, and purgeable pages — the latter
two are immediately reclaimable, giving a more realistic estimate than free pages alone.

**`/proc/meminfo` — Linux pseudo-filesystem**
On Linux, kernel state is exposed as text files under `/proc`. `/proc/meminfo` contains
memory statistics including `MemAvailable`, which accounts for free pages, reclaimable
caches, and kernel buffers. We parse it with `strip_prefix` + `trim` — standard string
processing, no external dependencies.

**Layered caps — defense in depth**
The three caps apply sequentially, each reducing the job count if needed:
1. CPU cap: `min(config.jobs, 2 × cores)` — prevents `spawn_blocking` oversubscription
2. RAM cap: `min(capped_jobs, available_ram / 1 GB)` — prevents OOM in stream mode
3. `buffer_unordered(effective_jobs)` — backpressure: a finished job frees its buffer
   before the next one allocates

This pattern — check once at startup, pick the most restrictive limit — avoids
runtime polling overhead while covering the common failure modes (too many CPU tasks,
too many in-memory buffers).

### What's next

Analysis and visualization of the extracted metadata — correlating clearnet URLs
with onion addresses across crawl dates.

---

## Step 10: Loops Instead of Recursion in `WarcRecordIter`

### What we built

`WarcRecordIter::next` used to skip each non-`response` record by calling
`return self.next();` — one extra stack frame per skipped record. A comment claimed
Rust would optimize the tail call away. It doesn't have to, and here it didn't: a
sampled WAT Archive contains 63,523 consecutive `metadata` records and a sampled WET
Archive 20,614 consecutive `conversion` records, enough to blow the stack of the
`bytes` and `memchr` strategies (`documentation/RESEARCH-warc-wat-wet.md` §4.5).

The fix wraps the whole record parse in an outer `loop` and replaces the recursive
call with `continue`, the same shape `WarcSliceIter` (mmap) already used. A new unit
test feeds 100,000 `metadata` records followed by one `response` through the
iterator; the old code aborts with `has overflowed its stack`, the new code yields
exactly the one record.

Also deleted `src/tmp_main.rs`: an untracked, uncompiled copy of `src/main.rs` from
commit `683b654`.

### Rust concepts introduced

**No guaranteed tail-call elimination**
Some languages (Scheme, Erlang) promise that a call in tail position reuses the
caller's stack frame, so tail recursion runs in constant stack space. Rust makes no
such promise. LLVM *may* turn a tail call into a jump in optimized builds, but not
in debug builds, and nothing in the language requires it. Explicit tail calls (the
reserved `become` keyword, RFC 3407) are not available on stable Rust 1.91.

**Destructors make "tail calls" not tail calls**
`return self.next();` looks like the last thing the function does, but it isn't:
the locals `target_uri` and `date` are `String`s, and their destructors run *after*
`self.next()` returns. The caller's frame must stay alive to run those destructors,
so the call is not in tail position at all. In Rust, any live value with a
destructor quietly defeats tail-call optimization.

**Stack overflow is an abort, not a panic**
Threads spawned by Rust currently get a 2 MiB stack by default — that includes test threads
and Tokio's `spawn_blocking` pool, where our parsers run. When recursion runs past
the guard page at the end of the stack, the runtime prints
`fatal runtime error: stack overflow` and aborts the whole process. Unlike a panic,
it can't be caught or unwound, so one pathological Archive would kill every
concurrent job.

**`loop` + `continue` — the iterator skipping idiom**
An iterator that must skip uninteresting items should loop inside `next()` until it
finds one to return, rather than recurse. The standard library does the same:
`Filter::next` calls `find` on the inner iterator, which loops. Stack usage is then
constant no matter how many items are skipped, and the final value leaves the loop
with an explicit `return`.

**`break` and `continue` target the innermost loop**
`next()` now nests the header-reading loops inside the outer record loop. A `break`
inside an inner loop exits only that loop; the `continue` in the skip branch sits
directly in the outer loop's body, so it restarts the record parse. When a
`continue` or `break` needs to reach an outer loop from inside an inner one, Rust
uses labels: `'record: loop { ... continue 'record; ... }`.

---

## Step 11: Characterization Tests for the Parse Functions

### What we built

Integration tests that pin what the six public parse functions (`parse_warc`,
`parse_warc_bytes`, `parse_warc_memchr`, `parse_warc_mmap`,
`parse_warc_bytes_from_memory`, `parse_warc_memchr_from_memory`) extract today. The
next step replaces all six with one `parse_archive`; these tests show whether that
changes the output, and where.

- `tests/common/mod.rs` -- shared helpers. `WarcBuilder` writes WARC records
  programmatically (computed `Content-Length`, unique `WARC-Record-ID`) and gzips
  each record as its own gzip member, as Common Crawl does. `Snapshot` turns a
  `ParseResult` into something comparable with `==`. `parse_with_every_function`
  runs all six functions on one Archive and `assert_all_agree` compares them.
- `tests/parse_characterization.rs` -- a hand-built fixture Archive of 10 records
  (`warcinfo`, then `request` / `response` / `metadata` for three pages) and three
  tests:
  - `fixture_yields_pinned_artifacts`: the exact onions, favicon URLs and inline
    favicons expected from the fixture, written out by hand.
  - `every_parse_function_agrees_on_fixture`: all six functions return the same
    `Snapshot`.
  - `every_parse_function_agrees_on_real_archive` (`#[ignore]`): the same check on a
    real downloaded Archive named by `REAL_WARC_ARCHIVE`.

The fixture covers an onion in an `Onion-Location` HTTP header, v2 and v3 onions in
the body (one twice on the same page, one in uppercase), `<link rel="icon">` with a
relative `href`, `<link rel="apple-touch-icon">`, `<meta name="msapplication-TileImage">`,
an inline `data:image/png;base64,...` favicon, a `text/plain` response containing
favicon markup, and an onion that only appears in `request` and `metadata` records.

Current behaviour the pinned test records, right or wrong:

- Onion search covers the whole HTTP response, headers included, and ignores
  `Content-Type`.
- Uppercase onions are not extracted: both engines match `[a-z2-7]` only.
- Favicon search only runs on `text/html` / `application/xhtml` responses, and adds
  a root `/favicon.ico` guess for every HTML page (to be dropped, ADR-0003).
- Only `response` records are searched.

Known gap, not covered by the fixture: the two onion engines disagree when a
non-ASCII letter touches the address. In `café3g2upl4pq6kufc4m.onion`, the memchr
engine sees `é`'s bytes as a word boundary and extracts the onion; `regex`'s Unicode
`\b` treats `é` as a word character and doesn't. The fixture stays ASCII so the
agreement test pins what the engines share.

On `CC-NEWS-20251001002341-04358.warc.gz` (1 GB) all six functions agree: 1 onion,
6,006 favicon URLs, 2 inline favicons; 54 s for all six in a release build.

```sh
cargo test                                   # fixture tests; real-Archive test ignored
REAL_WARC_ARCHIVE=download/CC-NEWS-...warc.gz \
  cargo test --release -- --ignored --nocapture
```

### Rust concepts introduced

**Integration tests in `tests/`**
Unit tests live next to the code in `#[cfg(test)] mod tests` and can reach private
items. Files in `tests/` are different: Cargo compiles each one as a separate crate
that links against the library, so it sees only `pub` items, imported by crate name
(`use onion_crawler::parse_warc_memchr;`). That is the right level for these tests:
they only touch the public API, so a refactor has to update them only where that API
changes, never because of internal changes.
Integration tests can use every crate in `[dependencies]` and `[dev-dependencies]`;
the fixture builder uses `flate2`'s `GzEncoder` without adding anything to
`Cargo.toml`.

**Shared test helpers: `tests/common/mod.rs`**
Every `.rs` file directly inside `tests/` becomes its own test binary. A helper file
at `tests/common.rs` would therefore show up as an empty test crate. Putting it in a
subdirectory as `tests/common/mod.rs` stops Cargo from compiling it on its own; each
test file that needs it declares `mod common;`. Each such test file compiles its own
copy, so a helper that one file doesn't use produces a dead-code warning in that
crate.

**Characterization tests**
A characterization test asserts what code *does*, not what it *should* do. The classic
recipe (Michael Feathers, *Working Effectively with Legacy Code*) is to run the code
and record its output. Here the expected values were written by hand from reading the
fixture first, and the first run confirmed them; a value only copied from a run would
also have pinned any behaviour nobody had noticed. The pinned values include behaviour
we plan to change (the `/favicon.ico` guess), so when the refactor changes it, the
test diff shows exactly that line and nothing else.

**`#[ignore = "reason"]`**
Marks a test that `cargo test` skips and lists as `ignored, <reason>`.
`cargo test -- --ignored` runs only the ignored tests; `-- --include-ignored` runs
everything. The real-Archive test also checks its environment variable with
`std::env::var_os` and returns early when it is unset, so `--ignored` passes cleanly
on a machine without a downloaded Archive.

**`CARGO_TARGET_TMPDIR`**
Cargo sets this variable when compiling integration tests and benchmarks: a scratch
directory inside `target/`. `env!("CARGO_TARGET_TMPDIR")` reads it at compile time,
so no temp-dir crate is needed. Tests run in parallel threads, so each one writes its
fixture to its own subdirectory; `parse_warc_mmap` also writes a decompressed `.warc`
next to the Archive, which must not collide either.

**Consuming builders**
`WarcBuilder`'s methods take `self` by value and return it, so an Archive reads as one
chain: `WarcBuilder::new().warcinfo(..).request(..).response(..).finish()`. Taking
ownership means a half-built value can't be reused by accident after `finish()`
consumes it.

**Comparing values the library can't compare**
`OnionSource` and `FaviconSource` don't derive `PartialEq`, and the refactor replaces
them anyway. Rather than change production code for the tests, the tests convert a
`ParseResult` into their own `Snapshot` type, and each source into their own
`Sighting`. `impl From<ParseResult> for Snapshot` is allowed in the test crate because
the orphan rule only needs *one* side of the impl to be local: here `Snapshot` is.
When the library types change, the conversions change but the hand-written expected
values don't. `Snapshot` uses `BTreeMap` instead of `HashMap`: equality is the same, but
`Debug` prints keys in sorted order, so a failure prints the same diff every time.

**Generic helper with an `Into` bound**
`OnionSource` and `FaviconSource` each get an `impl From<...> for Sighting`. One
function then converts lists of either: `fn sightings<T: Into<Sighting>>(sources:
Vec<T>) -> Vec<Sighting>`. Implementing `From` gives `Into` for free (the standard
library has a blanket `impl<T, U: From<T>> Into<U> for T`), so bounds are usually
written with `Into`, the direction the caller needs.

---

## Step 12: One `parse_archive`, Extractors per Artifact Kind

### What we built

The six `parse_warc*` functions are gone. Each one hard-wired the onion and favicon
searches into its own copy of the record loop, so adding an Artifact kind meant editing
all six. They are replaced by one function that only connects three independent choices:

```rust
pub fn parse_archive(
    transport: Transport,                 // how the bytes arrive
    shard: &Shard,                        // which Shard they belong to
    extractors: &mut [Box<dyn Extractor>], // what to extract
) -> Result<(), Box<dyn Error + Send + Sync>>
```

- **Transport** (`lib.rs`): `Disk(PathBuf)`, `Memory(Vec<u8>)` or `Mmap(PathBuf)`. Disk
  and Memory share one streaming loop (`File` and `Cursor<Vec<u8>>` are both `Read`);
  Mmap decompresses to a temporary `.warc` and uses the slice parser.
- **Format** (`page_record.rs`): every record becomes a `PageRecord::Warc(WarcResponse)`
  (page URL, crawl date, full HTTP response) that borrows the parser's bytes.
  `split_http_response` / `is_html_content` moved here, behind `WarcResponse::html_body()`.
- **Artifact kind** (`extractor.rs`): `trait Extractor` with one implementation per kind.
  `OnionExtractor` searches the whole HTTP response, headers included, with either engine
  (`OnionEngine::Memchr` or `OnionEngine::Regex`); `FaviconExtractor` scans HTML bodies.
  The loop hands each record to every extractor and never names a kind.
- **Domain types** (`artifact.rs`): `ArtifactKind`, `Shard` (the Archive file name without
  `.warc.gz`), and `Sighting { page_url, date, shard }`, which replaces both `OnionSource`
  and `FaviconSource`. The "same page already listed?" check, previously copied in nine
  places, now lives in one place: `add_sightings` (during extraction) and `merge_sightings`
  (per-Archive merge in `main`, and the `merge` subcommand) both call it.

Behaviour changes, each visible as one line in the characterization test diff:

- JSON shape: `{"page_url", "date", "shard"}` instead of `{"url", "date", "archive"}`;
  `shard` drops the `.warc.gz` suffix. Existing output files are not converted, and
  are no longer silently lost either: `load_results_from` / `load_favicons_from` used
  to turn any file they couldn't parse into an empty map, which the next save then
  wrote over the old results. They now return an error naming the file, and the crawl
  stops before writing anything (`tests/output_state.rs`).
- No root `/favicon.ico` guess for every HTML page (ADR-0003): only declared favicons.
- Inline `data:` favicons are no longer part of the parse result. They were never saved
  anyway; they come back as their own Artifact kind.
- Both onion engines use ASCII word boundaries. The regex pattern is now
  `(?-u:\b)([a-z2-7]{16}|[a-z2-7]{56})\.onion(?-u:\b)`, matching memchr's
  `is_word_boundary_byte`. Before, `café3g2upl4pq6kufc4m.onion` was found by memchr but
  not by the regex engine, whose Unicode `\b` counts `é` as a word character. The
  fixture now contains such a case, and every Transport × engine pair must agree on it.

The CLI is unchanged for now: `-s bytes` means the Regex engine, `-s memchr` the Memchr
engine, `-s mmap` the Mmap Transport with Memchr, `-m` the Memory Transport. The next
step replaces these with `--transport` and `--onion-engine`. `-s baseline` is gone: the
original `warc`-crate parser is now a standalone benchmark,

```sh
cargo run --release --example baseline -- download/CC-NEWS-...warc.gz
```

On `CC-NEWS-20251001002341-04358.warc.gz` (1 GB, release build) all six Transport ×
engine pairs agree: 1 onion and 4,884 favicon URLs (6,006 before: 1,122 root `/favicon.ico`
URLs existed only as guesses, no page declared them). Disk and Memory take ~6.3 s each, Mmap ~9.7 s (it writes
the decompressed copy first); the baseline example finds the same onion in 15.9 s.

### Rust concepts introduced

**Trait objects: `Box<dyn Extractor>`**
`OnionExtractor` and `FaviconExtractor` are different types with different sizes, so a
`Vec` can't hold both directly. `Box<dyn Extractor>` stores each on the heap behind a
*fat pointer*: the data pointer plus a pointer to a *vtable*, a per-type table of the
trait's methods. `extractor.extract(record, shard)` looks the method up in that table at
runtime (*dynamic dispatch*). Generics (`fn parse_archive<E: Extractor>`) would dispatch
statically and inline better, but one list could then hold only one extractor type; the
set of kinds is chosen at runtime, which is exactly what trait objects are for. The cost,
one indirect call per record per extractor, disappears next to gzip decompression.

**`self: Box<Self>` receivers**
`into_sightings(self: Box<Self>) -> Sightings` consumes the extractor to move its results
out without cloning. A plain `self` receiver needs to know the concrete type's size,
which a `dyn Extractor` doesn't have, so such a method couldn't be called on a trait
object. Taking `self` *through the box* works: the box has a known size, and the method
receives ownership of the heap value.

**Enums with data**
`Transport::Memory(Vec<u8>)` carries the downloaded bytes, `Transport::Disk(PathBuf)` the
file to read. Each variant holds exactly what that way of reading needs, so a "memory"
transport without bytes cannot be built and `parse_archive` has no invalid case to
check. `match transport { Transport::Memory(data) => ... }` moves the bytes out of the
enum and into the parser in the same step. `OnionExtractor` uses the same idea privately:
the public `OnionEngine` is a plain choice (`Memchr` / `Regex`), turned once into an
`OnionSearch` enum that holds the built `memmem::Finder` or compiled `Regex`.

**Lifetimes in `PageRecord<'a>`**
`PageRecord<'a>` holds `&'a str` and `&'a [u8]` instead of owned `String`s and `Vec`s.
`'a` names how long the borrowed bytes live, and the compiler rejects any use of a
`PageRecord` after its source is gone. One type now serves both parsers: on the
streaming path it borrows the current `WarcRecord`'s buffers, on the mmap path it borrows
a region of the mapped file. In both cases it lives for one loop iteration, and nothing is
copied to build it. On the mmap path `String::from_utf8_lossy` returns a `Cow<str>` that
borrows the header bytes whenever they are valid UTF-8, so even the URL is usually not
copied (the old code called `.to_string()` on every record).

**Exhaustive `match` on a one-variant enum**
`PageRecord` has a single variant today, yet the extractors `match` on it rather than
reaching into it. When a `Wat` variant is added, every such `match` stops compiling until
it handles WAT records: the compiler lists exactly the places a new Format affects.

**The newtype pattern: `Shard(String)`**
A tuple struct wrapping one `String`. At runtime it is a `String`; to the compiler it is
a different type, so an Archive file name can't be passed where a Shard is expected, and
`Shard::from_archive_name` is the one place the `.warc.gz` suffix is stripped. `serde`
serializes a newtype as its inner value, so in JSON a Shard is a plain string.

**Re-exports with `pub use`**
`lib.rs` declares the new modules `pub mod artifact;` etc. and also re-exports their main
types: `pub use artifact::{Shard, Sighting, ...};`. Callers write
`use onion_crawler::Sighting;` instead of `onion_crawler::artifact::Sighting`, and the
module layout can change later without breaking them.

**Dev-dependencies and examples**
Each file in `examples/` is a small program of its own, linked against the library like
an outside crate (`use onion_crawler::onion_search::ONION_PATTERN;`). Cargo builds
examples only on request (`cargo run --example baseline`, and `cargo test` builds them
to check they compile). Examples, tests and benchmarks may use `[dev-dependencies]`;
the library and binary may not. Moving `warc` there means `cargo build` no longer
compiles it, while the benchmark that needs it still works.

**Errors instead of defaults: `unwrap_or_default` vs `?`**
`serde_json::from_str(&content).unwrap_or_default()` reads as "use an empty map if
parsing fails", which sounds harmless until the empty map is saved over the file. The
loaders now return `Result<Sightings, Box<dyn Error>>`, and `?` passes a failure up to
`main`, which decides to stop. `.map_err(|err| format!("cannot load {}: {}", path, err))?`
adds the file name on the way: `format!` builds a `String`, and `?` converts it into a
`Box<dyn Error>` through the standard library's `From<String>` impl. A default is
the right fallback only when losing the data it replaces is acceptable.

**ASCII word boundaries in `regex`: `(?-u:\b)`**
`(?-u:...)` turns Unicode mode off for the enclosed part of the pattern, so `\b` checks
only `[0-9A-Za-z_]` on each side. It is also cheaper: a Unicode `\b` can force the
`regex` crate off its fast DFA when the input contains non-ASCII bytes.

---

## Step 13: Processed State per (Shard, Kind), New CLI, Crate Rename

### What we built

A run can now extract any subset of Artifact kinds, and a later run can add a kind
without redoing the work already done (ADR-0002). The crate is renamed `onion-crawler` →
`cc-extract` (version 2.0.0: the CLI changed in incompatible ways).

- **`processed.log` per (Shard, kind)**: each line is `<shard> <kind>`, such as
  `CC-MAIN-20260305070756-20260305100756-00000 onion`. Before, a line held the Archive file
  name, so a Shard processed once was skipped forever, even for a kind added later. Lines
  without a known kind (every line written before this step) are ignored: they don't say
  which kinds were extracted, so those Shards are processed again.
- **Scheduling**: for each Archive in the paths file, `main` computes the requested kinds
  not yet done for its Shard. None missing: skipped. Otherwise the Archive is scheduled
  with only those kinds' extractors (`new_extractor`). `--limit` counts scheduled Archives.
- **Save, then mark**: after a Shard finishes, each kind's Sightings are merged, its JSON
  file saved, and only then is `<shard> <kind>` appended (`save_then_mark`). The old code
  marked the Archive first and saved after, so a crash in between lost that Archive's
  results for good.
- **Only requested kinds are loaded and saved**: `-e onion` never reads or writes
  `favicons.json`. File names come from `ArtifactKind::output_filename()`; the per-kind
  `load_results_from` / `load_favicons_from` / `merge_results` / `merge_favicons` pairs are
  replaced by `load_sightings_from`, `save_sightings_to` and `merge_sightings_from`, which
  take the kind as a parameter.
- **`merge`** loops over `ArtifactKind::all()` and merges every kind whose file exists in
  at least one input directory. It fails if no directory has any results file.
- **CLI**: `-s/--strategy` and `-m/--stream` are gone, replaced by three independent options:

  | New option | Values | Default |
  |------------|--------|---------|
  | `-e/--extract` | comma-separated Artifact kinds | `onion,favicon` |
  | `-t/--transport` | `disk`, `memory`, `mmap` | `disk` |
  | `--onion-engine` | `memchr`, `regex` | `memchr` |

  The old flags map as follows: `-s memchr` = defaults, `-s bytes` = `--onion-engine regex`,
  `-s mmap` = `-t mmap`, `-m` = `-t memory`. The RAM guard now applies to `-t memory`.

```sh
cargo run -- warc.paths -e onion            # onions only
cargo run -- warc.paths -e onion,favicon    # same Shards: only favicon runs
```

The end-to-end test `tests/crawl_cli.rs` does exactly this on a fixture Archive, checks that
the second run extracts `favicon` only, and that the output directory ends up with the same
Sightings and `processed.log` lines as a single `-e onion,favicon` run.

### Rust concepts introduced

**`clap::ValueEnum` on a library type**
`#[derive(ValueEnum)]` on `ArtifactKind` and `OnionEngine` turns each variant into a CLI
value, kebab-cased (`Onion` → `onion`; a future `InlineFavicon` → `inline-favicon`), with the
variant's doc comment as its help text. The derive also generates `value_variants()`, the
list of all variants, which `ArtifactKind::all()` returns, so a new kind is listed
everywhere without editing a hand-maintained array. `Display` is built from
`to_possible_value()` and `FromStr` from `ValueEnum::from_str`, so the CLI, progress
output and `processed.log` share one spelling per kind; a log written with `Display` is
always readable with `parse()`.

`Transport` can't derive `ValueEnum`: its variants carry a path or the downloaded bytes,
which don't exist when the command line is parsed. `main` has a fieldless
`TransportChoice` enum for the option, and each task turns it into a `Transport` once the
Archive is downloaded.

**Fully qualified syntax: `<Self as ValueEnum>::from_str`**
`ArtifactKind` implements both `FromStr` and `ValueEnum`, and both traits have a
`from_str` method. Inside `impl FromStr`, a plain `Self::from_str(..)` would be ambiguous
(the compiler reports error E0034 and stops). `<Self as ValueEnum>::from_str(name, false)`
says which trait's method is meant.

**Comma-delimited lists in `clap`**
A `Vec<T>` field makes an option take several values. `value_delimiter = ','` also splits
one argument on commas, so `-e onion,favicon` and `-e onion -e favicon` give the same
`Vec`. `default_value = "onion,favicon"` is split the same way and shown as typed in
`--help`; the typed alternative, `default_values_t = [..]`, would display as
`onion favicon`, which is not how the user writes it. Repeats (`-e onion,onion`) are
removed with `sort()` then `dedup()`: `dedup` only drops *adjacent* equal elements, so
sorting first is what makes it remove all of them. Sorting needs `Ord`, now derived on
`ArtifactKind` (declaration order).

**`HashSet` of tuples**
`load_processed_from` returns `HashSet<(Shard, ArtifactKind)>`. Tuples implement `Hash` and
`Eq` whenever all their fields do, so the pair is a set element with no extra code, and
"is `onion` done for this Shard?" is `processed.contains(&(shard.clone(), kind))`. The
`clone` is needed because `contains` takes a reference to a whole tuple, and a tuple
of references `(&Shard, ArtifactKind)` is a different type; one small allocation per check
is negligible next to downloading an Archive.

**`filter_map` with `?` inside the closure**
Each `processed.log` line goes through a closure returning `Option`:
`let (shard, kind) = line.split_once(' ')?;` returns `None` for a line without a space,
`kind.parse::<ArtifactKind>().ok()?` for an unknown kind. `filter_map` keeps only the
`Some` values, so ignoring malformed lines takes no `if`/`continue` at all.

**`BTreeMap` for a stable order**
The loaded results are a `BTreeMap<ArtifactKind, Sightings>`. A `HashMap` would work too,
but would iterate in a different order every run, shuffling the kinds in the summary
lines. A `BTreeMap` iterates in key order (`Ord`), so output is the same every time.

**Ordering for crash safety**
Two writes that belong together (save the results, record the pair as done) can't happen
atomically, so their order decides what a crash between them leaves behind:

- save, then mark: results saved, pair not marked. The next run redoes the Shard for that
  kind; `merge_sightings` skips the Sightings already in the file, so the redo costs time
  and changes nothing.
- mark, then save: pair marked, results lost, and no later run looks for them again.

The rule is: write the data first, the record that the data exists last. `save_then_mark`
does both with `?` between them, so a failed save returns before the mark is written. It
is also the only public way to mark a pair: `mark_processed_in` is private, so no caller
can get the order wrong. `tests/output_state.rs` checks the failure case by putting a
*directory* where `onions.json` should be written. Writing then fails even for root, which
file permissions alone would not guarantee.

**End-to-end tests of a binary: `CARGO_BIN_EXE_<name>`**
Before running integration tests, Cargo builds the package's binaries and passes each
path at compile time as `env!("CARGO_BIN_EXE_cc-extract")`. `tests/crawl_cli.rs` runs it
with `std::process::Command`, setting `current_dir` to a scratch directory whose
`download/` already holds the fixture Archive, so the binary skips the download and needs
no network. The test compares the *loaded* output, not the bytes: a `HashMap` is
serialized in a different order each run, so two identical results files rarely match
byte for byte.

**`#[allow(dead_code)] mod common;`**
`tests/crawl_cli.rs` uses only `WarcBuilder` and `http_response` from the shared helpers.
Each test crate compiles its own copy of `common`, so the helpers it doesn't use would
each raise a dead-code warning; the attribute on the `mod` line silences them for that
crate only.
