// onion-crawler — Step 1: Read WARC archive paths from a file
//
// This program reads a text file containing Common Crawl WARC archive paths
// and prints each path with its line number. It demonstrates foundational
// Rust concepts: CLI argument parsing, error handling with Result, buffered
// I/O, iterators, pattern matching, and formatted output.

use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process;

fn main() {
    // --- CLI Arguments ---
    // `env::args()` returns an iterator over command-line arguments.
    // `.nth(1)` consumes the iterator up to index 1 (the first user arg;
    // index 0 is the program name) and returns Option<String>.
    // `unwrap_or_else` provides a default when None — here we fall back
    // to "warc.paths" so the program works with no arguments.
    let path = env::args().nth(1).unwrap_or_else(|| "warc.paths".to_string());

    // --- Error Handling with Result ---
    // `File::open` returns Result<File, io::Error>. Rather than panicking
    // on failure, we use `unwrap_or_else` to print a human-readable error
    // to stderr and exit with a non-zero status code.
    let file = File::open(&path).unwrap_or_else(|err| {
        eprintln!("Error: cannot open '{}': {}", path, err);
        process::exit(1);
    });

    // --- Buffered I/O ---
    // Wrapping the File in a BufReader adds an in-memory buffer (default 8 KB).
    // Without it, each `.read_line()` call would trigger a syscall. With it,
    // data is read in large chunks and served from the buffer — far fewer
    // syscalls for the same result.
    let reader = BufReader::new(file);

    // --- Iterators + Pattern Matching ---
    // `.lines()` returns an iterator of Result<String, io::Error>, lazily
    // reading one line at a time (zero-cost abstraction — no Vec allocated).
    // `.enumerate()` wraps each item as (index, value), giving us line numbers.
    let mut count = 0;
    for (index, line_result) in reader.lines().enumerate() {
        // `match` on the Result: Ok(line) gives us the string, Err(err)
        // lets us report the problem without crashing the whole program.
        match line_result {
            Ok(line) => {
                // {:>4} right-aligns the number in a 4-character-wide field,
                // producing neat columns: "   1 | crawl-data/..."
                println!("{:>4} | {}", index + 1, line);
                count += 1;
            }
            Err(err) => {
                // `eprintln!` writes to stderr, keeping stdout clean for
                // actual data — important when piping output.
                eprintln!("Warning: could not read line {}: {}", index + 1, err);
            }
        }
    }

    // Summary to stderr so it doesn't pollute piped output
    eprintln!("Read {} paths from '{}'", count, path);
}
