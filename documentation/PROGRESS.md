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
