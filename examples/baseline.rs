// Baseline benchmark — the project's original parsing approach
//
// Before the custom WARC parser and the extractors, every Archive was read
// with the `warc` crate, and every response body was copied into a UTF-8
// `String` and searched with `regex::Regex`. This example keeps that
// approach as a yardstick: it counts the unique .onion addresses in one
// Archive and reports how long that took.
//
//     cargo run --release --example baseline -- download/CC-NEWS-...warc.gz
//
// Compare its time and count with the main pipeline on the same Archive.
// It uses the same `ONION_PATTERN` as the extractors, so the counts match
// and only the reading technique differs.
//
// ## Examples and dev-dependencies
//
// Each file in `examples/` is a small program of its own, linked against
// the library like an outside user would (`use onion_crawler::...`). Cargo
// builds examples only on request (`cargo run --example`, `cargo test`),
// and they may use `[dev-dependencies]`. That is why `warc` can be a
// dev-dependency: the library and the `onion-crawler` binary no longer
// compile it at all.

use std::collections::HashSet;
use std::env;
use std::error::Error;
use std::process;
use std::time::Instant;

use onion_crawler::onion_search::ONION_PATTERN;
use regex::Regex;
use warc::{RecordType, WarcReader};

fn main() -> Result<(), Box<dyn Error>> {
    // `args_os` instead of `args`: a path that isn't valid UTF-8 still works.
    let Some(path) = env::args_os().nth(1) else {
        eprintln!("Usage: cargo run --release --example baseline -- <archive.warc.gz>");
        process::exit(2);
    };

    let onion_re = Regex::new(ONION_PATTERN)?;
    let mut onions: HashSet<String> = HashSet::new();
    let mut records_scanned: u64 = 0;
    let start = Instant::now();

    for record in WarcReader::from_path_gzip(&path)?.iter_records() {
        // The original skipped records the `warc` crate couldn't parse.
        let Ok(record) = record else {
            continue;
        };
        if *record.warc_type() != RecordType::Response {
            continue;
        }
        records_scanned += 1;

        // The step later strategies removed: copying the whole body into a
        // `String` (replacing invalid UTF-8) before searching it.
        let body = String::from_utf8_lossy(record.body());
        for m in onion_re.find_iter(&body) {
            onions.insert(m.as_str().to_string());
        }
    }

    println!(
        "{} response record(s), {} unique .onion address(es) in {:.1?}",
        records_scanned,
        onions.len(),
        start.elapsed()
    );
    Ok(())
}
