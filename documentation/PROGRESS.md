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

Step 2: Download a single WARC archive over HTTP using the `reqwest` crate, introducing
dependencies, async Rust, and writing bytes to disk.
