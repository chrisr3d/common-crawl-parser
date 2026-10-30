# Progress Journal

What each step changed, and the Rust concepts it introduced. A feature that a later step
replaced is described in a line or two, naming what replaced it; its concepts stay, as they
still hold. Fixes get a short paragraph each.

## Steps 1–2: Reading the Paths File, Downloading Archives

### What we built

A binary that reads a paths file (one Archive path per line) and downloads each Archive from
`https://data.commoncrawl.org/` into `download/`, streamed to disk, skipping the files already
there, with `--limit N`. The first downloader used the blocking `ureq` crate, replaced by async
`reqwest` in Step 6; `std::env::args()` gave way to `clap` after 1.0.0.

### Rust concepts introduced

**`Result<T, E>` and `?`**
Rust has no exceptions: a function that can fail returns `Ok(value)` or `Err(error)`. `?`
returns the error from the current function, or unwraps the value, converting the error type
on the way when the function returns `Box<dyn Error>`.

**`Box<dyn Error>`**
A heap pointer to any type implementing `Error`, so one function can fail with an `io::Error`,
an HTTP error or anything else through one return type, still printable with `Display`.

**`match`**
Exhaustive pattern matching: the compiler checks that every variant is handled, such as
`Ok(line)` and `Err(err)`.

**`BufReader` and lazy iterators**
`BufReader` reads a file in 8 KB chunks instead of one system call per read. `.lines()` yields
one line at a time, `.enumerate()` pairs each with its index and `.take(n)` stops after `n`;
nothing is collected into a `Vec` (a *zero-cost abstraction*).

**`println!` vs `eprintln!`**
Data goes to stdout, diagnostics to stderr, so `cargo run | head -5` shows only the data.
`{:>4}` right-aligns a value in a 4-character field.

**`Path` / `PathBuf`, `create_dir_all`, `File::open` / `File::create`**
`Path` and `PathBuf` are a borrowed and an owned path, as `&str` and `String`; `.join()` adds a
component with the OS's separator. `fs::create_dir_all` is `mkdir -p`: it succeeds when the
directory exists, so the program works on its first run and its hundredth. `File::open` reads;
`File::create` writes, creating or truncating the file.

**`impl Trait` parameters, `Read` and `Write`**
`fn download_with_progress(reader: impl Read, writer: impl Write, ...)` accepts any reader and
any writer: the compiler builds one copy per concrete type (generics, written more briefly).
Written against the traits, the function works with files, network streams or memory buffers.

**`str::parse::<T>()`**
The turbofish `::<usize>` names the type to parse into; bad input comes back as an `Err`, not
a panic.

**Temporaries in method chains**
In `.into_body().with_config().reader()`, each intermediate value must live as long as the next
call borrows it. Splitting the chain into `let` bindings lets the borrow checker see that it
does.

---

## Steps 3–5: WARC Parsing, Onion Extraction, Deduplication

### What we built

Each Archive is decompressed, its `response` records searched for `.onion` addresses with a
regex, and the results saved to `output/onions.json`. `output/processed.log` lists the Archives
done: a run skips those, parses an Archive already in `download/`, and downloads the rest.
`--delete` removes an Archive once parsed. Two fixes followed: an Archive parsed twice no longer
lists itself twice under an onion (`Vec::contains` before pushing: on 1 to 5 entries a linear
scan beats hashing, and keeps the order), and results are saved after each Archive, not once at
the end.

Since replaced: the `warc` crate by our own parser (Step 7; `warc` lives on in
`examples/baseline.rs`), the JSON shape (Steps 8 and 12), the log's lines and the order of
saving and marking (Step 13).

### Rust concepts introduced

**`HashMap` and the entry API**
`results.entry(onion).or_default()` returns the value for a key, inserting a default first if
it is missing: one lookup instead of two.

**`HashSet`**
Unique values with average O(1) lookup: the Archives already done, the onions already found in
one Archive.

**Use the data's structure**
The `warc` crate parses record boundaries and headers, so only `response` records are searched,
30 to 50 % of the data. Scanning every decompressed byte had also fed images and fonts,
multi-megabyte "lines" without a newline, to the regex.

**Compile a `Regex` once**
`Regex::new` builds an automaton, which is costly: once, outside the loop. `find_iter` then
yields every non-overlapping match.

**`serde_json` without derives**
`serde_json::to_string_pretty` takes any `Serialize` type; `HashMap`, `Vec` and `String`
implement it already (blanket implementations).

**`OpenOptions`**
Combines opening flags: `.append(true).create(true)` is the shell's `>>`, so the log never loses
earlier lines.

**`Cow<str>` from `String::from_utf8_lossy`**
*Clone on write*: it borrows the bytes when they are valid UTF-8, and allocates a `String`, with
U+FFFD for each invalid sequence, only when they are not.

---

## Performance: the Cost of `(?i)`

Parsing a 1 GB Archive took ~2.5 minutes in a release build, against ~17 s for the old crawler;
decompression and WARC parsing were ~15 s of it, the regex the rest. Its `(?i)` combined with
Unicode `\b` pushes the `regex` crate off its fast DFA and its literal search for `.onion`, to
run the full automaton at every byte. The old crawler's case-sensitive pattern was 1,250x
faster:

| Regex | Time (4.5 GB text, release) |
|---|---|
| `(?i)\b[a-z2-7]{16}\.onion\b\|\b[a-z2-7]{56}\.onion\b` | 125.6 s |
| `\b([a-z2-7]{16}\|[a-z2-7]{56})\.onion\b` | 0.1 s |

Regex performance is not intuitive: benchmark the pattern on real data (the
[`regex` docs](https://docs.rs/regex/latest/regex/#performance) describe its strategies).
Step 24 matches any case again, with classes listing both cases instead of `(?i)`.

**`[profile.dev.package."*"]`: optimized dependencies in debug builds**
`opt-level = 2` under this profile optimizes every dependency (decompression, regex, parsing)
while our own crate stays debuggable. A 1 GB Archive: ~16 s in release, ~1 min 20 s in debug.

```toml
[profile.dev.package."*"]
opt-level = 2
```

---

## Step 6: Concurrent Downloads and Parsing with Tokio

### What we built

Up to `--jobs N` Archives download and parse at once, each parse starting as soon as its
download ends. `async fn main()` runs on Tokio's multi-threaded runtime, `reqwest` replaces
`ureq`, parsing (CPU-bound) runs on Tokio's blocking pool, and results are merged on the main
task, one Archive at a time. Then:

- `--jobs` defaults to the number of logical CPUs, and `--limit` to no limit.
- Each Archive reports its download and parse times, and the summary their averages.
- `reqwest` uses `rustls` instead of OpenSSL, so building needs no system TLS library:
  `reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }`.

### Rust concepts introduced

**`async` / `await`**
An `async fn` returns a `Future`, a computation not yet finished. `.await` suspends the task and
hands the thread back to the runtime, which runs another task meanwhile, so thousands of network
waits share a few threads.

**The Tokio runtime**
Futures need an executor to poll them. `#[tokio::main]` starts a multi-threaded runtime (one
worker per core) that schedules tasks and wakes them on I/O events (`epoll`, `kqueue`) and
timers.

**`spawn_blocking`**
CPU-heavy or blocking work on an async worker stalls every task sharing that thread.
`tokio::task::spawn_blocking` moves it to a pool meant for blocking, and the async task awaits
the result. Rule of thumb: anything that blocks for more than a few microseconds.

**`reqwest` streaming**
`.send().await` and each `.chunk().await` release the thread while the network is slow, where
four `ureq` downloads held four blocked threads.

**`buffer_unordered(N)`**
A stream combinator that polls up to N futures at once and yields each result as it finishes,
not in submission order, so a fast download never waits for a slow one: bounded concurrency
without a semaphore.

**`Arc<T>`**
Tokio tasks need `'static` data, so they can't borrow from `main`. `Arc` (atomic reference
count) gives a value several owners: `Arc::clone` increments a counter, and the value is dropped
with the last `Arc`. It shares read-only access; mutation would need `Arc<Mutex<T>>`, which
merging on the main task avoids.

**Pinning: `pin_mut!`**
A future is a state machine that may point into itself, so it must not move once polled.
`futures::pin_mut!` pins a stream on the stack before it is polled.

**Fan out, fan in**
Independent work runs concurrently; shared state (the results, the files) is updated on one
task, in sequence: no locks, no races.

**`available_parallelism` and `Instant`**
`std::thread::available_parallelism()` returns the logical CPU count as a `NonZeroUsize`
(at least 1; `.get()` gives the `usize`), replacing the `num_cpus` crate. `Instant::now()` and
`.elapsed()` measure time on a monotonic clock, which NTP can't move backwards.

---

## After 1.0.0: `clap`, Gzip Paths Files, a Library Crate

### What we built

- A `clap` derive struct replaces the hand-written argument loop; the paths file is a required
  positional argument.
- A paths file ending in `.gz`, as Common Crawl publishes them, is decompressed as it is read.
- `main.rs` keeps the CLI and the orchestration; the rest moves to `lib.rs`.

### Rust concepts introduced

**`clap` derive**
`#[derive(Parser)]` on a struct generates the parser: a field without `short`/`long` is
positional, `#[arg(short, long)]` makes a flag, a `String` without a default is required, and
types are parsed and `--help` written for free. `///` comments become the help text, so notes
for the reader of the code use `//`.

```rust
#[derive(Parser)]
struct Config {
    /// Path to the WARC-paths file (supports .gz)
    input: String,
    /// Maximum number of archives to process (default: all)
    #[arg(short, long)]
    limit: Option<usize>,
}
```

**`Option` and `if let`**
`limit: Option<usize>` puts "maybe absent" in the type, where `0` meant "no limit" before.
`if let Some(limit) = config.limit { ... }` runs the block only for `Some`, with `limit` bound
inside it.

**`Box<dyn BufRead>`**
A gzip reader and a plain reader are different types; boxing either as a `dyn BufRead` lets one
variable hold both. Calls go through a vtable at runtime, a cost that doesn't matter for a file
read once.

**Reusing transitive dependencies**
`libflate` was already compiled for the `warc` crate; listing it in `Cargo.toml` only made it
importable. `cargo tree` shows what is already there.

**A binary and a library in one package; `pub`**
`main.rs` imports the library by crate name. Items are private to their module unless `pub`, so
the library decides what it exposes, and tests and other binaries can use it too.

---

## Step 7: Ripgrep-Style Parsing

### What we built

Techniques from ripgrep, each measurable on its own: a WARC parser of our own
(`src/warc_parser.rs`), search on raw bytes, a SIMD search for the literal `.onion`
(`src/onion_search.rs`), memory-mapped parsing, and SIMD gzip decompression. An 864 MB Archive
went from ~16 s to ~5.6 s. They were four `--strategy` values (`baseline`, `bytes`, `memchr`,
`mmap`), which Steps 12 and 13 split into the two choices they mixed: the Transport
(`-t disk|memory|mmap`) and the onion engine (`--onion-engine memchr|regex`).

### Rust concepts introduced

**`regex::bytes::Regex`**
`regex::Regex` searches `&str`, valid UTF-8 only; `regex::bytes::Regex` searches any `&[u8]`.
Searching the raw bytes saves converting each record body to a `String`: only the match, 22 to
62 bytes, is converted.

**`memchr::memmem::Finder`: find the literal, then validate**
ripgrep's key idea: take the literal every match contains (`.onion`), find it with SIMD (16 to
32 bytes per cycle with SSE2/AVX2 or NEON), and check the bytes around each hit with plain
comparisons. `.onion` is rare (0 to 2 hits per 50 to 500 KB body), so the check almost never
runs.

**`#[inline(always)]`**
For tiny predicates in hot loops (`is_onion_char`), it asks the compiler to inline the body at
every call site, across modules too: no call, and the code is optimized within the loop.

**Parse only what you need**
The `warc` crate parses every header with `nom` into a `HashMap` per record. `WarcRecordIter`
keeps only `WARC-Type` and `Content-Length` and skips other records' bodies through a stack
buffer, so ~60 % of the decompressed data never reaches the heap. `parse_ascii_usize` reads
`Content-Length` with a loop over ASCII digits, without the UTF-8 check, error type and generic
dispatch of `str::parse`.

**`memmap2::Mmap` and `unsafe`**
Mapping a file puts its bytes in the process's address space: pages load on access, and body
slices point into the mapping, uncopied. Gzip must be decompressed first, so the mmap path
writes a decompressed copy, 3 to 5 times the Archive's size. `Mmap::map` is `unsafe` because
another process could change the file while it is mapped, which the compiler can't rule out;
`unsafe` means "the programmer upholds this", stated in a comment, in a block kept small.

**Zero-copy parsing: `WarcSliceIter`**
On one contiguous `&[u8]`, the parser returns body slices instead of `Vec<u8>`s and finds the
`\r\n\r\n` ending each header block with `memmem`. The streaming parser can't: it reuses its
buffer.

**`flate2` with `zlib-ng`**
Decompression bounds every Transport, so the SIMD-optimized zlib-ng backend speeds all of them.
It is built from C source, needing a C compiler and `cmake`; `libflate` stays for paths files.

```toml
flate2 = { version = "1", features = ["zlib-ng"], default-features = false }
```

**`clap::ValueEnum`**
`#[derive(ValueEnum)]` lets `clap` parse an enum's variants as an option's values and list them
in `--help`, each variant's doc comment as its help.

---

## Step 8: The Page and Date of Each Onion

### What we built

Each onion maps to where it was seen: the page URL (`WARC-Target-URI`), the crawl date
(`WARC-Date`) and the Archive, deduplicated on (URL, Archive). Both parsers read the two
headers: as owned `String`s when streaming, as `&[u8]` slices into the mapping on the mmap path.
Step 12 turned the record into `Sighting { page_url, date, shard }`, shared by every kind.

### Rust concepts introduced

**`serde` and `#[derive(Serialize, Deserialize)]`**
`serde` defines traits describing a type in an abstract data model, and companion crates
(`serde_json`, `toml`, ...) write the formats. The derive generates that code at compile time,
as fast as hand-written, field names becoming JSON keys. A struct of our own needs it, where
`HashMap` and `Vec` didn't.

---

## Step 9: Parsing from Memory; Resource Guards

### What we built

`--stream` downloaded an Archive into a `Vec<u8>` and parsed it there, writing nothing to disk;
it is `-t memory` since Step 13. With ~1 GB per job, many such jobs could exhaust RAM, so the
number of jobs is capped at startup by the CPUs and, in memory, by the available RAM.

### Rust concepts introduced

**`std::io::Cursor`**
Wraps a `Vec<u8>` (any `AsRef<[u8]>`) as a `Read` + `Seek`, like a `File`. `MultiGzDecoder<R:
Read>` and `WarcRecordIter<R: BufRead>` were already generic, so reading from memory needed no
change to the parser.

**Moving into `spawn_blocking`**
`spawn_blocking(move || parse(data))` hands the 800 MB `Vec` to the blocking thread by copying
three words (pointer, length, capacity), never the bytes. The async task can't touch it
afterwards; use after move, a dangling pointer in C, doesn't compile.

**`Vec::with_capacity`**
With the `Content-Length` known, the buffer is allocated once at full size, where growing by
doubling would reallocate and copy ~30 times on the way to 800 MB.

**`#[cfg(target_os = "...")]`**
Conditional compilation, checked by the compiler: the source has three `get_available_memory()`
(macOS, Linux, fallback), and exactly one is compiled.

**Asking the OS for free memory**
macOS: `std::process::Command` runs `sysctl -n <key>` (~1 ms, once, no `unsafe` or C bindings),
counting free, speculative and purgeable pages. Linux: `MemAvailable` from `/proc/meminfo`, read
with `strip_prefix` and `trim`.

**Layered caps**
Each guard can only lower the job count: 2x the cores (N downloads overlapping N parses), then
the RAM, then `buffer_unordered`, under which a finished job frees its buffer before the next
one fills its own. Checked once at startup. Step 14 divides the RAM by the largest Plan instead
of 1 GB.

---

## Step 10: Loops Instead of Recursion in `WarcRecordIter`

`WarcRecordIter::next` skipped each unwanted record with `return self.next();`, one stack frame
per record. A WAT Archive holds 63,523 `metadata` records in a row, a WET Archive 20,614
`conversion` records: enough to overflow the stack. The record parse now sits in a `loop` and
skipping is `continue`, as in `WarcSliceIter`; a test feeds 100,000 `metadata` records, then one
`response`.

**No guaranteed tail calls**
Rust doesn't promise tail-call elimination: LLVM may apply it in release builds, not in debug
ones (`become`, for explicit tail calls, is not stable in Rust 1.91). Here the call wasn't even
in tail position: the `String` locals `target_uri` and `date` are dropped *after* it returns, so
the frame had to stay.

**Stack overflow aborts**
Threads get 2 MiB of stack by default, test threads and Tokio's blocking pool included. Running
past it prints `fatal runtime error: stack overflow` and aborts the process: not a panic,
nothing to catch, and every concurrent job dies with it.

**`loop` and `continue` to skip items**
An iterator's `next()` loops until it has an item, as `Filter::next` does: constant stack,
however many items it skips. `break` and `continue` act on the innermost loop; a label
(`'record: loop { ... continue 'record; }`) reaches an outer one.

---

## Step 11: Characterization Tests

### What we built

Tests pinning what the six `parse_warc*` functions extracted, before Step 12 replaced them with
one. `tests/common/mod.rs` builds WARC records in code (`WarcBuilder`: `Content-Length`
computed, one gzip member per record as Common Crawl writes them) and turns results into a
comparable `Snapshot`. `tests/parse_characterization.rs` parses a 10-record fixture, checks the
exact Artifacts and that every way of parsing agrees, and, when asked, checks the same on a real
Archive:

```sh
REAL_WARC_ARCHIVE=download/CC-NEWS-...warc.gz cargo test --release -- --ignored --nocapture
```

The pinned values included behaviour to change later (a guessed `/favicon.ico` per HTML page,
missed uppercase onions: Steps 12 and 24). The same tests now compare every Transport and onion
engine.

### Rust concepts introduced

**Integration tests in `tests/`**
Each file in `tests/` is a crate of its own linked to the library: it sees only `pub` items, by
crate name, so internal refactors don't break it. It may use `[dev-dependencies]`, and
`[dependencies]` too: the fixture is gzipped with `flate2`'s `GzEncoder`.

**Shared helpers in `tests/common/mod.rs`**
Every `.rs` file directly in `tests/` becomes a test binary; a subdirectory's `mod.rs` doesn't.
Each test file declares `mod common;` and compiles its own copy, so helpers it doesn't use warn
as dead code; `#[allow(dead_code)] mod common;` silences that for one file.

**Characterization tests**
They assert what code *does*, right or wrong (Michael Feathers, *Working Effectively with Legacy
Code*). The expected values were written by hand from the fixture, then confirmed by a run:
values copied from a run would also pin behaviour nobody noticed. When a refactor changes
something on purpose, the test's diff shows that line alone.

**`#[ignore = "reason"]`**
`cargo test` skips the test and says why; `-- --ignored` runs only ignored tests,
`-- --include-ignored` all of them. The real-Archive test also returns early when its variable is
unset (`std::env::var_os`).

**`CARGO_TARGET_TMPDIR`**
A scratch directory in `target/` that Cargo gives integration tests, read at compile time with
`env!`: no temp-dir crate. Tests run in parallel, so each writes to its own subdirectory.

**Consuming builders**
`WarcBuilder`'s methods take and return `self`, so an Archive is one chain
(`WarcBuilder::new().warcinfo(..).response(..).finish()`), and `finish()` consumes it: a
half-built value can't be reused by accident.

**Test-side types, `From`, and the orphan rule**
Rather than change production code, the tests convert results into their own `Snapshot`, built
on `BTreeMap` so `Debug` prints keys sorted and a failure shows the same diff every time. The
`From` impl is allowed in the test crate because one side, `Snapshot`, is local (the *orphan
rule*). Implementing `From` gives `Into` for free, so bounds are written `T: Into<Sighting>`.

---

## Step 12: One `parse_archive`, One Extractor per Artifact Kind

### What we built

The six `parse_warc*` functions, each wiring the onion and favicon searches into its own copy of
the record loop, became one function connecting three independent choices (Step 15 added the
Format as a parameter):

```rust
pub fn parse_archive(
    transport: Transport,                  // how the bytes arrive
    shard: &Shard,                         // which Shard they belong to
    extractors: &mut [Box<dyn Extractor>], // what to extract
) -> Result<(), Box<dyn Error + Send + Sync>>
```

- **Transport** (`lib.rs`): `Disk(PathBuf)`, `Memory(Vec<u8>)` or `Mmap(PathBuf)`. Disk and
  Memory share the streaming loop; Mmap decompresses to a copy and uses the slice parser.
- **Format** (`page_record.rs`): each record becomes a `PageRecord::Warc(WarcResponse)`
  borrowing the parser's bytes; `WarcResponse::html_body()` holds the HTML check.
- **Artifact kind** (`extractor.rs`): `trait Extractor`, one implementation per kind. The loop
  hands every record to every extractor and never names a kind.
- **Domain types** (`artifact.rs`): `ArtifactKind`, `Shard` (the Archive name without its
  suffix) and `Sighting { page_url, date, shard }`. The "same page already listed?" check,
  copied in nine places, is now in one.

Behaviour changes, each one line of the characterization test's diff:

- The JSON is `{"page_url", "date", "shard"}`, where it was `{"url", "date", "archive"}`. A
  results file that can't be parsed stops the run with its name, where it used to load as empty
  and be overwritten by the next save.
- No guessed root `/favicon.ico`: never checked to exist, it was nearly a third of the URLs
  saved.
- Inline `data:` favicons leave the results: never saved, they return in Step 18 as a kind.
- Both onion engines use ASCII word boundaries, `(?-u:\b)` in the regex. Before,
  `café3g2upl4pq6kufc4m.onion` was found by memchr only, the regex's Unicode `\b` counting `é` as
  a letter; the fixture now pins it.
- `-s baseline` is gone: the `warc`-crate parser is the benchmark `examples/baseline.rs`.

On a 1 GB CC-NEWS Archive all six Transport × engine pairs agree: 1 onion, 4,884 favicon URLs
(6,006 before, 1,122 of them guesses). Disk and Memory take ~6.3 s, Mmap ~9.7 s (it writes the
copy first), the baseline 15.9 s.

### Rust concepts introduced

**Trait objects: `Box<dyn Extractor>`**
Extractor types differ in size, so a `Vec` can't hold them directly. A `Box<dyn Extractor>` is
a *fat pointer*: the data, plus a *vtable* of the type's trait methods looked up at each call
(*dynamic dispatch*). Generics dispatch statically but allow one type per list, and the kinds
are chosen at runtime. One indirect call per record per extractor is nothing next to gzip.

**`self: Box<Self>`**
`into_findings(self: Box<Self>)` consumes the extractor to move its results out without a clone.
A plain `self` needs the concrete type's size, which a `dyn Extractor` lacks; through the box,
the size is known.

**Enums with data**
`Transport::Memory(Vec<u8>)` carries the bytes, `Transport::Disk(PathBuf)` the path: each variant
holds what its way of reading needs, so an invalid Transport can't be built, and `match` moves
the data out as it picks the branch. Privately, `OnionExtractor` turns the plain `OnionEngine`
choice into an `OnionSearch` holding the built searcher.

**Lifetimes: `PageRecord<'a>`**
`PageRecord<'a>` holds `&'a str` and `&'a [u8]` borrowed from the parser (the current record's
buffers, or the mapping), and the compiler rejects any use after they are gone. Building one
copies nothing; on the mmap path even the URL stays borrowed, through `from_utf8_lossy`'s `Cow`.

**Exhaustive `match`, no `_` arm**
`PageRecord` had one variant, yet the extractors `match` on it. When Step 15 added `Wet`, the
build failed at each such `match`: a list of every place that has to decide what a WET record
means. A `_` arm would have compiled silently.

**Newtype: `Shard(String)`**
A tuple struct around a `String`: the same at runtime, a different type to the compiler, so an
Archive file name can't pass for a Shard. `serde` writes it as the inner string.

**`pub use` re-exports**
`lib.rs` re-exports the main types (`pub use artifact::{Shard, Sighting, ...};`), so callers
write `cc_extract::Sighting` and the modules can move without breaking them.

**Dev-dependencies and examples**
Each file in `examples/` is a program linked to the library like an outside crate, built on
request (`cargo run --example baseline`; `cargo test` checks it compiles). Examples and tests may
use `[dev-dependencies]`, the library may not, so moving `warc` there keeps it out of
`cargo build`.

**Errors, not defaults**
Since Step 8, `serde_json::from_str(..).unwrap_or_default()` had turned an unreadable results
file into an empty map, which the next save wrote over the file. The loaders now return a
`Result`, and `.map_err(|err| format!("cannot load {}: {}", path, err))?` passes the error up
with the file's name (`?` boxes the `String` through `From<String>`). A default fits only where
losing what it replaces is fine.

**`(?-u:\b)`: ASCII word boundaries**
`(?-u:...)` turns Unicode off inside it, so `\b` checks `[0-9A-Za-z_]` only. It is also faster:
a Unicode `\b` can push `regex` off its DFA on non-ASCII input.

---

## Step 13: Processed State per (Shard, Kind), New CLI, Crate Rename

### What we built

A run extracts any subset of kinds, and a later run adds a kind without redoing the rest. The
crate became `cc-extract` 2.0.0 (it was `onion-crawler`), as the CLI changed.

- **`processed.log` lines are `<shard> <kind>`**, where an Archive name used to mark a Shard
  done for every kind, forever. Old lines name no kind and are ignored, so their Shards are
  redone.
- **Scheduling**: a Shard runs with only the requested kinds not yet done (none: skipped);
  `--limit` counts scheduled Shards.
- **Save, then mark** (`save_then_mark`): each kind's file is saved, then its line appended. The
  old code marked first, so a crash in between lost the results.
- **Only the requested kinds are loaded and saved**, by one set of functions taking the kind
  (`load_sightings_from`, `save_sightings_to`, `merge_sightings_from`); `merge` covers every
  kind with a file.
- **CLI**: `-s/--strategy` and `-m/--stream` became three independent options: `-e/--extract`
  (kinds, default `onion,favicon`), `-t/--transport` (`disk`, `memory`, `mmap`) and
  `--onion-engine` (`memchr`, `regex`).

`tests/crawl_cli.rs` runs `-e onion`, then `-e onion,favicon` on the same Shards: the second run
extracts `favicon` only, and the output equals that of one `-e onion,favicon` run.

### Rust concepts introduced

**`ValueEnum` on a library type**
On `ArtifactKind`, each variant becomes a kebab-cased value (`InlineFavicon` →
`inline-favicon`) with its doc comment as help, and `value_variants()` lists them all, so a new
kind shows up everywhere with no list to update. `Display` and `FromStr` are built on it, so the
CLI, the progress output and `processed.log` share one spelling. `Transport` can't derive it, as
its variants carry data unknown when arguments are parsed; `main` has a fieldless
`TransportChoice` instead.

**Fully qualified syntax**
`ArtifactKind` has a `from_str` from both `FromStr` and `ValueEnum`, so `Self::from_str` is
ambiguous (error E0034); `<Self as ValueEnum>::from_str(name, false)` picks one.

**Comma-separated values in `clap`**
A `Vec<T>` field with `value_delimiter = ','` reads `-e onion,favicon` as `-e onion -e favicon`,
and `default_value = "onion,favicon"` is split the same way and shown as typed. `sort()` then
`dedup()` drops repeats, as `dedup` only drops *adjacent* equal items (sorting needs `Ord`,
derived in declaration order).

**`HashSet` of tuples**
A tuple is `Hash` and `Eq` when its fields are, so `HashSet<(Shard, ArtifactKind)>` takes no
code. `contains(&(shard.clone(), kind))` clones because a tuple of references is another type.

**`filter_map` with `?` in the closure**
For each log line, a closure returning `Option` runs `line.split_once(' ')?` and
`kind.parse().ok()?`; `filter_map` keeps the `Some`s, so malformed lines go without an `if`.

**`BTreeMap` for a stable order**
It iterates in key order, so the summary lists the kinds the same way on every run, where a
`HashMap` would shuffle them.

**Ordering writes for crash safety**
Two writes that can't be made atomic together: their order decides what a crash between them
leaves. Save then mark, and the Shard is redone, `merge_sightings` skipping the Sightings already
saved. Mark then save, and the results are lost and never looked for again. Data first, the
record that it exists last. `save_then_mark` is the only public way to mark, so no caller can get
the order wrong; its test puts a *directory* where `onions.json` goes, which fails even as root.

**End-to-end tests: `CARGO_BIN_EXE_<name>`**
Cargo builds the binaries before the integration tests and passes their paths as
`env!("CARGO_BIN_EXE_cc-extract")`. The test runs it in a scratch directory whose `download/`
already holds the fixture, so no network is needed, and compares loaded results, not bytes
(`HashMap` order varies).

---

## Step 14: The Planner: Formats, Datasets, Multi-Archive Shards

### What we built

Each Shard is planned before download: the cheapest Formats serving every requested kind, one
Archive per Format, each handed to the kinds that read it. Only WARC could be read yet, so every
Plan was WARC; Steps 15 and 16 add WET and WAT.

- **`src/format.rs`**: `Format { Warc, Wat, Wet }` (suffix, directory, estimated size: 1 GB,
  170 MB, 70 MB), `FormatSet`, and `Dataset { CcMain, CcNews }`, read from the path prefix, with
  the Formats each publishes.
- **`ArchivePath`**: a Shard's three Archives differ only in the last directory and the suffix,
  so any one locates the others, and the input can be a WARC, WAT or WET paths file.
- **`src/plan.rs`**: `cheapest_fit` (a kind's cheapest accepted combination within some
  Formats) and `cheapest_plan` (the cheapest subset of the Dataset's Formats that every kind
  fits in).
- **`--formats`** forces the Plan. It is rejected at startup if it can't serve a kind
  (`Error: cannot extract favicon from wet: it needs warc`), and for a Shard whose Dataset lacks
  one of its Formats.
- **Per Shard**: every Archive of the Plan is downloaded, each parsed with the extractors of the
  kinds reading it, and their Sightings unioned. A kind is saved and marked only if every Archive
  it reads parsed (`Plan::split_done`), so a failed download no longer stops kinds that don't
  need it. With `-t memory`, the available RAM is divided by the largest Plan.

### Rust concepts introduced

**A static table as a `match`**
`ArtifactKind::format_requirement` returns each kind's accepted combinations from a `match`. A
`HashMap` would fail at runtime on a kind without an entry; a `match` must cover every variant,
so such a kind doesn't compile. Its type, `&'static [&'static [Format]]`, needs no `static`
item: slices built from constants are stored once in the binary (*constant promotion*).

**Bitmasks as small sets**
`FormatSet(u8)` gives each Format a bit (`1 << format as u8`, `as u8` giving a fieldless
variant's position). Union is `a | b`; "`a` inside `b`" is `a & !b == 0`. The newtype keeps a set
from mixing with other numbers.

**Enumerating subsets**
A subset only clears bits, so counting from 1 to the set's value and keeping the numbers inside
it visits every non-empty subset (seven at most):
`(1..=self.0).map(FormatSet).filter(move |subset| subset.is_subset_of(self))`.
`.map(FormatSet)` passes the tuple struct's constructor as a function.

**`min_by_key`**
Returns the item with the smallest key, or `None` from an empty iterator, so "nothing fits"
needs no separate check. The key comes from a closure, so `FormatSet` needs no `Ord`; a tie
keeps the first.

**`FromIterator`; collecting into `Result` and `Option`**
Implementing `FromIterator<Format> for FormatSet` makes it a `collect()` target. Collecting
`Result`s into `Result<Vec<_>, _>` stops at the first `Err` and returns it (`Plan::within`);
`Option` works the same way.

**A typed error**
`enum PlanError` has a variant per reason, carrying the facts, and `Display` writes the message;
tests compare variants, so rewording breaks none. `impl Error for PlanError {}` is empty
(`Error` only needs `Debug` and `Display`) and lets `?` box it.

**Let chains**
Edition 2024 joins `let` patterns with `&&` in one `if`, each binding visible to the next
condition; Clippy's `collapsible_if` suggests them for nested `if`s.

```rust
if let Some(forced) = forced
    && let Err(err) = Plan::within(forced, &kinds)
{
```

---

## Step 15: Reading WET Archives

### What we built

A WET Archive is a WARC file of `conversion` records, one per HTML page, holding its visible
text. `Format::record_type()` names the record type holding the pages (`response`, `metadata`,
`conversion`); both parsers take it and skip every other record. `parse_archive` takes the
Format as a parameter, as a `Memory` Transport has no file name to tell it. The new
`PageRecord::Wet(WetConversion { page_url, date, text })` is searched for onions; favicons have
nothing to find there. WET alone finds about a third of the onions, most sitting in HTTP headers
and attributes, so no Plan used it until Step 16 paired it with WAT. `tests/wet_archive.rs`
builds a WET fixture.

### Rust concepts introduced

**`&'static str` fields**
`WarcRecordIter` keeps its record type as a `&'static str`: a string literal lives for the whole
program, so the struct needs no lifetime parameter, where `&'a str` would have tied every
iterator to the string's owner.

**`unreachable!` behind an entry check**
`parse_archive` then rejected `Format::Wat` up front, so the WAT arm building a `PageRecord`
could never run. `unreachable!` panics if that ever proves false, instead of inventing a value;
naming the arm, not `_`, keeps the `match` exhaustive.

**`BTreeMap::from([...])` and const generics in `std`**
`BTreeMap::from([(k1, v1), (k2, v2)])` builds a map in one expression: the standard library
implements `From<[(K, V); N]>` once for every length `N`, through a *const generic* parameter.

---

## Step 16: Reading WAT Archives; WAT + WET Plans

### What we built

With WAT readable, the cheaper Plans apply: on CC-MAIN, the default `-e onion,favicon` downloads
WAT + WET (~240 MB per Shard) instead of WARC (~1 GB), `onion` reading both and `favicon` WAT
only. A WAT Archive holds one JSON `metadata` record per WARC record, three per page, written by
ia-web-commons: the WARC and HTTP headers and, for HTML, the `<link>` and `<meta>` tags of the
`<head>` and every link.

- **`PageRecord::Wat(WatMetadata)`**: a SIMD search for `"WARC-Type":"response"` drops, without
  parsing them, the two records in three not made from a `response`; the rest are parsed once,
  into structs declaring only the path down to `Head`. The crawl date is inside the JSON, so a
  record whose JSON can't be read is skipped.
- **Onions** are searched in the raw JSON, which keeps addresses as WARC does with three
  exceptions: onions only in the plain text are gone (WET has them), one right after an escape
  such as `\n` is missed, and one in the page URL is found.
- **Favicons** come from `Head`, resolved against `<base href>`; `data:` URLs are skipped, as
  ia-web-commons cuts them short. The `rel` and `name` checks are shared with the HTML scanner.
- **Requirements**: `onion` accepts WARC or WAT + WET, `favicon` WARC or WAT. The planner needed
  no change.
- **Tests**: `tests/wat_archive.rs` writes the same pages as WARC, WAT and WET; WAT + WET find
  what WARC finds.

### Rust concepts introduced

**Partial deserialization**
The `Deserialize` structs declare only the fields read. serde skips every other key, checking
its JSON but building nothing, so the large `Links` array costs a scan, not a `Vec`
(`#[serde(deny_unknown_fields)]` would reject such keys instead). `#[serde(rename = "...")]` maps
keys that aren't Rust identifiers, and a level that may be missing is an `Option`.

```rust
#[derive(Deserialize)]
struct WatJson<'a> {
    #[serde(rename = "Envelope", borrow)]
    envelope: Envelope<'a>,
}
```

**Borrowing from the input: `Cow<'a, str>`**
`serde_json::from_slice` can return strings pointing into its input. A string with an escape
(`\/`, `\u00e9`) can't be borrowed, its decoded text not being in the input, so a `&'a str` field
would fail the parse. A `Cow<'a, str>` holds either a `Borrowed` or an `Owned` string, and both
read as `&str`.

**`#[serde(borrow)]` and the `Option<Cow>` pitfall**
A `Cow` field borrows only when marked `#[serde(borrow)]`, and only as the field's own type:
`Option<Cow<'a, str>>` always allocates. Optional strings are plain `Cow`s with
`#[serde(default)]`: a missing key reads as `""`, which allocates nothing.

**`Cow` for a value computed only sometimes**
`favicons_in_head` borrows the page URL as its base, and builds a `String` only for a page with
a `<base href>`.

**Returning a shorter borrow**
`page_url(&self) -> &'a str` lends the URL for the record's whole life. `date` can't: a WAT date
may be an owned `String` inside the `WatMetadata`, so `date(&self) -> &str` borrows from `self`
(elision ties the result to `&self`).

**`LazyLock`: a `static` built on first use**
`memmem::Finder::new` picks its algorithm at runtime, so a `static` can't be built at compile
time. `std::sync::LazyLock` runs its closure on first use and keeps the result, thread-safely:

```rust
static RESPONSE_TYPE: LazyLock<memmem::Finder<'static>> =
    LazyLock::new(|| memmem::Finder::new(br#""WARC-Type":"response""#));
```

**`const fn`**
`format_requirement` returns constant slices, so it can be a `const fn`, and the planner tests
take their constants from the real table
(`const ONION: FormatRequirement = ArtifactKind::Onion.format_requirement();`).

---

## Step 17: WARC Favicons Honour `<base href>`

### What we built

The HTML scanner resolves relative favicon URLs as a browser does: against the first `<base>`
with an `href` (itself resolved against the page URL), else against the page URL. WARC and WAT
now agree: on `https://example.net/docs/page.html` with `<base href="/static/">`,
`icons/fav.png` becomes `https://example.net/static/icons/fav.png` in both. The scan for
`<base>` runs only once a favicon URL needs resolving, so pages without favicons pay nothing;
`document_base_url` is the one rule both Formats call. `tests/wat_archive.rs` pins a page with a
relative `<base>`.

### Rust concepts introduced

**`OnceCell`: computed on first use, through `&self`**
The scanners hold a `&DocumentBase`, and the base URL is computed the first time one asks.
Storing it through a shared reference is *interior mutability*, which the `std::cell` types
allow under rules: a `OnceCell` is set once, then only read, so every `&str` it hands out stays
valid.

```rust
struct DocumentBase<'a> {
    body: &'a [u8],
    page_url: &'a str,
    url: OnceCell<Cow<'a, str>>,
}

fn url(&self) -> &str {
    self.url.get_or_init(|| { /* scan for <base>, resolve it */ })
}
```

**`OnceCell`, `LazyCell`, `LazyLock`**
A `LazyCell` holds its closure, but a closure's type has no name, so every scanner taking one
would need a generic parameter; the struct holds what the closure would capture instead.
`LazyLock` is the thread-safe one, for `static`s; one page is scanned on one thread.

**`Option` as an iterator**
`Option` is `IntoIterator`, yielding its value if it has one, so the earlier of two tags that
may be missing is `[lower, upper].into_iter().flatten().min_by_key(|&(start, _)| start)`, with
no four-case `match`.

**`?` on `Option`**
`first_base_href_found_by` returns `None` at `finder.find(...)?` when no tag is left, and at
`find_tag_end(...)?` when one is cut short.

---

## Step 18: The `inline-favicon` Artifact Kind

### What we built

Base64 `data:` favicons, decoded since the first scanner and then thrown away, are a kind of
their own, saved in `inline_favicons.json`:

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

- **Key**: the SHA-256 of the image (`sha2` crate), so one image is one entry, on however many
  pages, with whatever line breaks.
- **`mmh3`**: Shodan's favicon hash (its `http.favicon.hash:` filter): MurmurHash3 x86_32,
  seed 0, of the base64 as Python's `codecs.encode` writes it (a newline every 76 characters and
  at the end), as a signed `i32`. Hand-written, as is the base64 encoder.
- **`media_type`**: from the `data:` header, lowercase, without parameters; only `;base64` URIs
  are decoded.
- **Plan**: WARC only (WAT cuts `data:` URLs, WET has no markup); not in the default `-e`.
- **`Findings`**: one type for every kind's results, `Sightings` or `InlineFavicons`, passed
  through the pipeline; deduplication stays in `merge_sightings`, now generic.
- **Tests**: published vectors for base64, MurmurHash3 and SHA-256; end to end, one PNG on two
  pages is saved once, with two Sightings and its hashes pinned from Python.

### Rust concepts introduced

**`sha2` and the `Digest` trait**
RustCrypto publishes a crate per hash family, all implementing `digest::Digest`:
`Sha256::digest(bytes)`. A cryptographic hash is worth a dependency, as a subtly wrong one shows
only when keys fail to match someone else's; MurmurHash3, a few dozen lines with published
vectors, is written by hand as teaching material.

**Why `DefaultHasher` is no identifier**
`HashMap`'s hash is left unspecified on purpose and may change in a later Rust release, breaking
every saved key; with 64 bits, a collision also becomes likely past ~5 billion inputs (the
birthday bound). Keys that are saved or shared need a standard hash: SHA-256 is the same in Rust,
Python and `sha256sum`.

**`#[serde(untagged)]`**
`untagged` writes a variant as its content alone, so `onions.json` keeps its shape. Reading back
can't be untagged (`{}` fits both variants), so the kind chooses, through `Findings::empty(kind)`,
the one `match` saying which kind has which shape.

```rust
#[derive(Serialize)]
#[serde(untagged)]
pub enum Findings {
    Sightings(Sightings),
    InlineFavicons(InlineFavicons),
}
```

**Generics over a trait; provided methods; the orphan rule**
`merge_sightings<E: ArtifactEntry>(into: &mut HashMap<String, E>, from: HashMap<String, E>)`
takes any map whose values hold Sightings, and the compiler builds one copy per `E`
(*monomorphization*). `add_sighting` is a *provided method*: implementors write `sightings_mut`
and inherit the deduplication. The trait is implemented for `Vec<Sighting>`, a `std` type,
which the orphan rule allows because the trait is ours.

**`std::mem::take`**
Moves a value out from behind a `&mut`, leaving its `Default` (an empty `Vec`) in its place:
no clone.

**Wrapping arithmetic, `rotate_left`, `chunks_exact`, `cast_signed`**
MurmurHash3 computes modulo 2³², and `*` and `+` panic on overflow in debug builds, so it says
`wrapping_mul` and `wrapping_add`; `rotate_left` is C's `(x << r) | (x >> (32 - r))`.
`chunks_exact(4)` yields whole 4-byte blocks and keeps the rest as its `remainder()`, and
`u32::from_le_bytes` reads a block as x86 does. `u32::cast_signed` (Rust 1.87) reads the same 32
bits as an `i32`, where `as i32` could be any conversion.

**`let ... else`**
`let PageRecord::Warc(response) = record else { return; };` binds the pattern, or leaves.

---

## Step 19: The Modular Refactor in Review; Docs and a SLURM Example

### What we built

Steps 10 to 18 in one table:

| | Before (`onion-crawler` 1.3.1) | After (`cc-extract` 2.0.0) |
|---|---|---|
| Kinds | `onion` and `favicon`, always both | Any of `onion`, `favicon`, `inline-favicon` (`-e`) |
| Formats | WARC only; WAT and WET crashed the parser | WARC, WAT, WET, planned per Shard |
| Download per CC-MAIN Shard, default kinds | ~1 GB | ~240 MB (WAT + WET) |
| Parsing | Six copy-pasted `parse_warc_*` functions | One `parse_archive`, one `Extractor` per kind |
| CLI | `-s/--strategy` and `-m/--stream` mixed Transport and search | `-t/--transport` and `--onion-engine`, independent |
| `processed.log` | Archive file names: a Shard done once was never redone | `<shard> <kind>`: a kind can be added later |
| Crash between save and mark | Results of the Archive lost | Shard redone, nothing lost (`save_then_mark`) |
| Favicons | Guessed root `/favicon.ico` on every page, `<base href>` ignored | Declared favicons only, resolved against `<base href>` |
| Inline favicons | Decoded, then dropped | Saved with SHA-256, Shodan `mmh3` and media type |

Adding a kind takes a variant in `ArtifactKind`, an `impl Extractor`, and an arm in each `match`
on the kind, which the compiler lists as none has a `_` arm. The documents caught up:
`FEATURES.md` rewritten for 2.0.0; the README shows `-h` verbatim, checked by
`tests/cli_help.rs`; `--jobs` no longer shows the core count of the machine printing the help as
its default; and `examples/slurm/crawl.sh` runs several processes per node, each with its own
`--offset`, `--limit` and `--output-dir`, which `merge.sh` then merges.

### Rust concepts introduced

**`include_str!`**
Reads a file at compile time into a `&'static str` (the path relative to the source file): a
missing README fails the build, and editing it rebuilds the test. `include_bytes!` gives bytes.

**Short and long help from one doc comment**
clap's `-h` shows a field's `///` comment up to its first blank line, `--help` all of it. A `//`
comment is invisible to clap.

**`default_value_t` and `hide_default_value`**
`default_value_t = default_jobs()` is evaluated at every start and printed by `--help`;
`hide_default_value = true` hides it, so the help can state the default in words.

**Testing the documentation through the binary**
The test runs the binary with `Command` and asserts the README *contains* its output. clap wraps
help to the terminal only with its `wrap_help` feature, not enabled here, so the output is the
same on every machine.

**Cargo's `examples/` discovery**
Cargo builds `examples/*.rs` and `examples/*/main.rs`; `examples/slurm/` has no `main.rs`, so its
scripts are no target.

---

## Steps 20–23: Fixes

### Step 20: Crash-Safe Writes

A kill (a SLURM time limit, `scancel`, the OOM killer, Ctrl-C) could leave a file cut short
under its final name: a truncated `onions.json`, which the next run refuses to load, or a partial
Archive in `download/`, parsed as if whole on every later run. Each file is now written under a
temporary name, then renamed once complete: results to `<file>.tmp`, downloads to
`<file name>.<process id>.part`, renamed only if the byte count matches `Content-Length` when
the server sent one. A `TempFile` guard removes the temporary file on error paths. No `fsync`: a
killed process's writes still reach the disk, and syncing hundreds of MB over a network
filesystem at every save would help only against a machine crash.

- **`fs::rename`** replaces a file in one atomic step, but only within one filesystem (`EXDEV`
  otherwise), so temporary files sit next to their target, not in `/tmp`.
- **`std::process::id`** makes the `.part` name unique among processes sharing `download/`.
- **A guard with `Drop`** runs its cleanup however the function is left, `?` included, and when
  an async task is cancelled, but not when the process is killed. `keep()` disarms it after the
  rename. Locals are dropped in reverse order of declaration.
- **`Stream` and `try_unfold`**: `futures::Stream` is the async `Iterator`. `save_archive` takes
  any stream of byte chunks, so tests need no network; `stream::try_unfold` turns `reqwest`'s
  `chunk().await` calls into such a stream.
- **`std::pin::pin!`** is the standard library's `pin_mut!` (Step 6).
- **`flush` before `rename`**: `tokio::fs::File` writes on a background thread, and
  `flush().await` waits for the last write.

### Step 21: `cargo fmt` and `cargo clippy` Clean; Paths File Read Errors

`cargo fmt -- --check` and `cargo clippy --all-targets -- -D warnings` pass on the whole crate,
the reformatting in a commit of its own so `git blame --ignore-rev` can skip it. Clippy's
`lines_filter_map_ok` found a bug: `reader.lines().filter_map(Result::ok)` dropped read errors,
so a `warc.paths.gz` cut short ran with the paths before the cut and exited 0. The first read
error now stops the run with exit 1.

- **`filter_map(Result::ok)` on `lines()`** makes a read error look like the end of the file,
  and loops forever on a reader failing on every call; `map_while(Result::ok)`, Clippy's
  suggestion, ends the loop but still hides the error. Collecting into
  `Result<Vec<String>, _>` stops at the first error and returns it.

### Step 22: The mmap Copy Without a Name

The `mmap` Transport's decompressed copy, `download/<name>.warc`, had the same name in every
process: a second process reaching the same Shard truncated the file the first had mapped,
killing it with `SIGBUS`, and a killed process left 3 to 5 GB behind. `parse_mmap` now creates
`<file name>.<process id>.mmap` with `create_new`, removes the name at once, then decompresses
into the open `File` and maps it: no other process can reach the copy, and the kernel frees it
when the parse ends or the process dies. Windows can't remove an open file, so there the copy
keeps its name until `TempFile` removes it. `tests/mmap_transport.rs` lists the directory during
the parse.

- **Unlinked open files**: a name is a directory entry pointing to the file, and the kernel frees
  the file once no name and no open handle or mapping is left. A kill closes every handle, so it
  leaves nothing, with no `Drop` needed. Meanwhile `df` counts the space; `ls` and `du` don't see
  it. NFS clients emulate this with a hidden `.nfsXXXX` file.
- **`OpenOptions::create_new`** creates the file or fails with `AlreadyExists`, in one system call
  (`O_CREAT | O_EXCL`), where `File::create` would truncate another process's file. It needs
  `read(true)` too, as a mapping requires a handle opened for reading.
- **`Mmap::map(&file)`** maps whatever the handle refers to, named or not; the `File`'s writes and
  the mapping share the page cache, so no flush is needed.
- **`#[cfg]` on a statement; a guard declared before it is assigned**: the Windows guard,
  `let _copy_name: TempFile;`, is assigned only once `create_new` succeeds. It is dropped last,
  and never if never assigned, so a failed `create_new` can't remove another process's file.
  `_copy_name` lives to the end of the function, where `let _ = ...` would drop it at once.
- **`Rc<RefCell<..>>`** in the test: several owners of one value, borrows checked at runtime.
  Neither is thread-safe (`Arc<Mutex<..>>` is), and the test needs no threads.

### Step 23: An Exit Status for Shards Left Undone

A run exited 0 even when Shards failed and were left for the next run, so `sacct` showed every
task COMPLETED. Now:

| Code | Meaning | Run again? |
|---|---|---|
| 0 | Every Shard taken on done for every requested kind | No need |
| 1 | Stopped early (paths or results file missing or unreadable, `--offset` past the end, ...) | Once the cause is fixed |
| 2 | Invalid option or value (`clap`) | Once the command is fixed |
| 3 | Ran to the end with some Shards left with kinds undone | Yes, the same command |

3, not 2: `clap` exits with 2 on misuse, and a wrapper retrying on 2 would retry a typo forever.
A failed save or `processed.log` append now leaves the kind undone too. `--help` lists the codes
(`after_long_help`), and `examples/slurm/crawl.sh` reports, per process, Shards to retry and
early stops.

- **`ExitCode` and `Termination`**: `main` may return any `Termination` type: `()` reports 0,
  `Result::Err` 1, an `ExitCode` its own value (`ExitCode::from(3u8)`: only the low 8 bits reach
  the parent). `#[tokio::main]` passes it through.
- **`process::exit` skips `Drop`**: it never returns (its type is `!`), so nothing above it is
  dropped: buffered writes are lost, `TempFile`s stay, the runtime isn't shut down. The early
  stops keep it, as they come before anything is written.
- **`after_help` / `after_long_help`**: text printed after both helps, or after `--help` only.

---

## Step 24: Onion Addresses in Any Case, v3 Checksums Verified

### What we built

Onion matching went by shape: 16 or 56 characters of `[a-z2-7]`, then `.onion`. An address in
uppercase or ending in `.Onion` was missed, and any 56 base32 characters passed for v3. Now:

- **Any case**, suffix included; every address is returned lowercase, as it is the Artifact
  key. `ONION_PATTERN` lists both cases (`[a-zA-Z2-7]`, `\.[oO][nN][iI][oO][nN]`) rather than
  using `(?i)` (see Performance).
- **v3 verified**: the 56 characters decode to `public key (32) || checksum (2) || version (1)`,
  and `checked_address` keeps the address only if the version is 3 and the checksum is the first
  2 bytes of `SHA3-256(".onion checksum" || public key || version)` (`sha3` crate; base32 by
  hand). Anything else is dropped silently. All 203 v3 addresses found in 99 Shards of
  CC-MAIN-2026-34 passed: the check guards against look-alikes, it changes no output seen so
  far.
- **v2 kept unchecked**: 16-character addresses carry no checksum; Tor dropped them in 2021.
- **One check**: both engines and `examples/baseline.rs` keep only what `checked_address`
  returns, so they still count the same onions.
- **No rules version**: `processed.log` doesn't record which rules extracted a pair, so the new
  rules apply from now on; a fresh `--output-dir` keeps results under one set of rules.
- **Tests**: uppercase, mixed case, `.Onion`, a wrong checksum, a version 4 address, page order.
  The old test address encoded version `0xD7`; its replacement is built from a made-up key: the
  first 51 base32 characters are free, the last five computed with Python's `hashlib`.

**The memchr engine in any case.** `memmem` compares bytes exactly, and `.onion` has 32
spellings. Bare scans over 1 GB of a decompressed WARC Archive:

| Scan | Time for 1 GB |
|---|---|
| `memmem` for `.onion` (the old engine, lowercase only) | 27 ms |
| `memmem` for `.o`, and again for `.O`, merged in order | 47 ms |
| Teddy (`aho-corasick`'s SIMD searcher) over `.o` and `.O` | 54 ms |
| Teddy over the 32 spellings, or the new `ONION_PATTERN` | 94 ms |
| `memchr` for `.`, then the next 5 bytes ignoring case | 230 ms |

The engine scans for `.o` and `.O` (`SuffixFinder`) and compares the rest ignoring case. Each
full `memmem` scan costs ~22 ms per GB, so doing better would take hand-written SIMD.

**Timings** (`-e onion --formats warc`, parse time, release builds):

| Archive | memchr, before → after | regex, before → after |
|---|---|---|
| CC-NEWS 1 GB, disk, 3 rounds | 6.0–6.1 → 6.1–6.2 s | 6.1 → 6.4 s |
| CC-NEWS 1 GB, memory | 6.0 → 6.1 s | 6.0 → 6.3 s |
| CC-MAIN 0.9 GB, disk | 4.7 → 4.7 s | 4.7 → 4.9 s |

memchr costs ~2 % more, regex ~5 %. The regex's cost can't be written away: every form tried
(classes, `(?i:onion)`, an ASCII-only `(?i)`) scans at 93 ms per GB, as `regex` searches the 32
spellings at once. With `-t memory`, the download (11 to 29 s) dwarfs either. On the CC-MAIN
Archive, old and new binaries wrote identical `onions.json` files with either engine, and
`baseline` counted the same 25 onions; on the CC-NEWS one, all found the same single onion.

### Rust concepts introduced

**Const generics**
`fn decode_base32<const N: usize>(text: &[u8]) -> Option<[u8; N]>` takes a value as a generic
parameter: `decode_base32::<35>` returns an array on the stack, sized at compile time, and the
check `text.len() * 5 != N * 8` reads as base32's definition (5 bits per character, 8 per byte).

**Base32 with a bit queue**
Each character's 5 bits are shifted into a `u16` (`bits = (bits << 5) | value`) and counted. Once
8 are waiting, the oldest go out as a byte (`(bits >> (pending - 8)) as u8`, `as u8` keeping the
low 8 bits) and a mask drops them; at most 7 + 5 bits are ever held.

**`Digest::chain_update`**
`Sha3_256::new().chain_update(a).chain_update(b).finalize()` hashes `a` then `b` as one buffer,
without copying them together; each call takes the hasher and returns it, builder-style.

**Merging sorted iterators: `Peekable` and `iter::from_fn`**
`find_iter` yields positions in order, one iterator per needle. `peek()` shows the next item
without taking it, so comparing the two peeks and taking the smaller merges them, as merge sort
does. `iter::from_fn(move || ...)` turns the closure into an iterator that ends at its first
`None`. `chain` would put every `.o` before every `.O`, out of page order.

**`impl Trait` captures lifetimes in edition 2024**
`fn candidates(&self, body: &[u8]) -> impl Iterator<Item = usize>` borrows both arguments.
Edition 2024 captures every lifetime in scope; earlier editions needed `+ '_`.

**`#[expect(lint, reason = "...")]`**
Clippy's `large_enum_variant` flags `OnionSearch`: 288 bytes for `Memchr`, 32 for `Regex`. There
is one per extractor, already boxed, so boxing the variant would only add a pointer to follow per
record. `#[expect]` (Rust 1.81) silences the lint with its reason and, unlike `#[allow]`, warns
once the lint stops firing.

**`checked_` names and `bool::then`**
Like `checked_add`, `checked_address` returns `None` rather than a wrong value.
`valid.then(|| ...)` is `Some` of the closure's result when `true`, and `None`, without running
it, when `false`; `filter_map` then keeps the `Some`s.
