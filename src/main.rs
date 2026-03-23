// onion-crawler — Steps 3–5: WARC Parsing, .onion Extraction, and Deduplication
//
// Building on Step 2's HTTP downloader, the pipeline now:
//   1. Downloads WARC archives from Common Crawl (using ureq)
//   2. Decompresses and parses them with the `warc` crate
//   3. Extracts .onion addresses via regex
//   4. Deduplicates results and persists them to JSON
//
// The program implements a three-state model for each archive:
//   - Already processed (in output/processed.log) → skip entirely
//   - Downloaded but not parsed (file exists in download/) → parse it
//   - Not downloaded → download first, then parse
//
// New concepts: HashMap, HashSet, OpenOptions, warc crate, regex, serde_json.

use std::collections::{HashMap, HashSet};
use std::env;
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process;

use regex::Regex;
use warc::{RecordType, WarcReader};

/// Base URL for Common Crawl data archives.
const COMMONCRAWL_BASE: &str = "https://data.commoncrawl.org/";

/// Default number of archives to process per run.
const DEFAULT_LIMIT: usize = 1;

/// File tracking which archives have been fully processed.
const PROCESSED_FILE: &str = "output/processed.log";

/// JSON file storing extracted .onion addresses and their source archives.
const RESULTS_FILE: &str = "output/onions.json";

// ---------------------------------------------------------------------------
// CLI Argument Parsing
// ---------------------------------------------------------------------------

/// Parsed command-line configuration.
struct Config {
    paths_file: String,
    limit: usize,
    delete: bool,
}

/// Parse command-line arguments into a `Config`.
///
/// Supports:
///   --limit N / --limit=N  → cap how many archives to process
///   --delete               → remove archive files after parsing
///   <positional>           → path to the WARC-paths file
fn parse_args() -> Config {
    let args: Vec<String> = env::args().skip(1).collect();

    let mut paths_file = String::from("warc.paths");
    let mut limit = DEFAULT_LIMIT;
    let mut delete = false;

    let mut i = 0;
    while i < args.len() {
        if let Some(value) = args[i].strip_prefix("--limit=") {
            limit = value.parse::<usize>().unwrap_or_else(|_| {
                eprintln!("Error: --limit value '{}' is not a valid number", value);
                process::exit(1);
            });
        } else if args[i] == "--limit" {
            i += 1;
            if i >= args.len() {
                eprintln!("Error: --limit requires a value");
                process::exit(1);
            }
            limit = args[i].parse::<usize>().unwrap_or_else(|_| {
                eprintln!("Error: --limit value '{}' is not a valid number", args[i]);
                process::exit(1);
            });
        } else if args[i] == "--delete" {
            delete = true;
        } else if args[i].starts_with('-') {
            eprintln!("Error: unknown flag '{}'", args[i]);
            process::exit(1);
        } else {
            paths_file = args[i].clone();
        }
        i += 1;
    }

    Config {
        paths_file,
        limit,
        delete,
    }
}

// ---------------------------------------------------------------------------
// State Management
// ---------------------------------------------------------------------------

/// Load the set of already-processed archive filenames.
///
/// `HashSet` stores unique values with O(1) average-case lookup via hashing.
/// It's the right tool when the core question is "have we seen this before?"
fn load_processed() -> HashSet<String> {
    let path = Path::new(PROCESSED_FILE);
    if !path.exists() {
        return HashSet::new();
    }

    let content = fs::read_to_string(path).unwrap_or_default();
    content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Append a filename to the processed log.
fn mark_processed(filename: &str) -> io::Result<()> {
    fs::create_dir_all("output")?;
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(PROCESSED_FILE)?;
    writeln!(file, "{}", filename)
}

/// Load existing results from the JSON file.
fn load_results() -> HashMap<String, Vec<String>> {
    let path = Path::new(RESULTS_FILE);
    if !path.exists() {
        return HashMap::new();
    }

    let content = fs::read_to_string(path).unwrap_or_default();
    serde_json::from_str(&content).unwrap_or_default()
}

/// Save the results map to the JSON file.
fn save_results(results: &HashMap<String, Vec<String>>) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all("output")?;
    let json = serde_json::to_string_pretty(results)?;
    fs::write(RESULTS_FILE, json)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Download Logic
// ---------------------------------------------------------------------------

/// Extract the filename component from a WARC URI path.
///
/// e.g. `crawl-data/CC-NEWS/.../CC-NEWS-20251001.warc.gz` → `CC-NEWS-20251001.warc.gz`
fn filename_from_uri(uri: &str) -> Result<&str, &'static str> {
    uri.rsplit('/')
        .next()
        .ok_or("URI has no filename component")
}

/// Download a single WARC archive from Common Crawl using `ureq`.
///
/// Streams the response body to disk in 8 KB chunks (via `Read` trait),
/// so memory usage stays constant regardless of archive size. Prints
/// progress every 10 MB.
fn download_warc(uri: &str) -> Result<bool, Box<dyn Error>> {
    let url = format!("{}{}", COMMONCRAWL_BASE, uri);
    let filename = filename_from_uri(uri)?;
    let local_path: PathBuf = Path::new("download").join(filename);

    if local_path.exists() {
        eprintln!("  [{}] Already downloaded, skipping download", filename);
        return Ok(false);
    }

    fs::create_dir_all("download")?;

    eprintln!("  [{}] Downloading...", filename);
    eprintln!("  [{}] URL: {}", filename, url);

    let response = ureq::get(&url).call()?;

    // Content-Length header tells us the total size (if the server provides it).
    let total_size: Option<u64> = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok());

    if let Some(size) = total_size {
        eprintln!("  [{}] Size: {:.1} MB", filename, size as f64 / 1_048_576.0);
    }

    // Stream the response body to a file in 8 KB chunks.
    // `into_body().into_reader()` gives us a `Read` implementor that
    // pulls bytes from the HTTP response. We read in fixed-size chunks
    // to keep memory usage constant.
    let mut reader = response.into_body().into_reader();
    let mut file = File::create(&local_path)?;
    let mut buf = [0u8; 8192];
    let mut bytes_written: u64 = 0;
    let mut last_report: u64 = 0;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])?;
        bytes_written += n as u64;

        if bytes_written - last_report >= 10 * 1_048_576 {
            last_report = bytes_written;
            match total_size {
                Some(total) => {
                    let pct = (bytes_written as f64 / total as f64) * 100.0;
                    eprint!(
                        "\r  [{}] Progress: {:.1} MB / {:.1} MB ({:.0}%)",
                        filename,
                        bytes_written as f64 / 1_048_576.0,
                        total as f64 / 1_048_576.0,
                        pct,
                    );
                }
                None => {
                    eprint!(
                        "\r  [{}] Progress: {:.1} MB",
                        filename,
                        bytes_written as f64 / 1_048_576.0,
                    );
                }
            }
        }
    }

    if last_report > 0 {
        eprintln!();
    }

    eprintln!(
        "  [{}] Done: {:.1} MB written",
        filename,
        bytes_written as f64 / 1_048_576.0,
    );

    Ok(true)
}

// ---------------------------------------------------------------------------
// WARC Parsing & .onion Extraction
// ---------------------------------------------------------------------------

/// Parse a WARC archive and extract unique .onion addresses.
///
/// Uses the `warc` crate for structured parsing: `WarcReader::from_path_gzip`
/// handles gzip decompression internally and yields typed records. We filter
/// to `RecordType::Response` (HTTP response bodies) where .onion links appear,
/// skipping request records, metadata, and binary content.
///
/// The regex scans each response body for both v2 (16-char) and v3 (56-char)
/// .onion addresses using base32 character classes.
fn parse_warc(path: &Path, onion_re: &Regex) -> Result<HashSet<String>, Box<dyn Error>> {
    let reader = WarcReader::from_path_gzip(path)?;
    let mut onions = HashSet::new();
    let mut records_scanned: u64 = 0;
    let filename = path.file_name().unwrap_or_default().to_string_lossy();

    for result in reader.iter_records() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };

        if *record.warc_type() != RecordType::Response {
            continue;
        }

        records_scanned += 1;

        let body = String::from_utf8_lossy(record.body());
        for m in onion_re.find_iter(&body) {
            onions.insert(m.as_str().to_lowercase());
        }

        if records_scanned % 10_000 == 0 {
            eprint!(
                "\r  [{}] Scanning: {} records, {} onion(s)",
                filename, records_scanned, onions.len()
            );
        }
    }

    if records_scanned >= 10_000 {
        eprintln!();
    }

    Ok(onions)
}

// ---------------------------------------------------------------------------
// Main — sequential processing loop
// ---------------------------------------------------------------------------

fn main() {
    // --- Parse CLI arguments ---
    let config = parse_args();

    eprintln!(
        "Reading WARC paths from '{}' (limit: {}, delete after: {})",
        config.paths_file, config.limit, config.delete
    );

    // --- Open and read the paths file ---
    let file = File::open(&config.paths_file).unwrap_or_else(|err| {
        eprintln!("Error: cannot open '{}': {}", config.paths_file, err);
        process::exit(1);
    });
    let reader = BufReader::new(file);

    let uris: Vec<String> = reader
        .lines()
        .filter_map(Result::ok)
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();

    if uris.is_empty() {
        eprintln!("No paths found in '{}'", config.paths_file);
        process::exit(1);
    }

    eprintln!("Found {} path(s) in file", uris.len());

    // --- Load persistent state ---
    let processed = load_processed();
    let mut results = load_results();

    eprintln!(
        "State: {} already processed, {} onion(s) in results\n",
        processed.len(),
        results.len()
    );

    // --- Compile the .onion regex once ---
    //
    // `Regex::new()` compiles the pattern string into an efficient automaton.
    // This compilation is expensive, so we do it once outside the loop.
    //
    // Important: we use a case-sensitive pattern (no `(?i)` flag). Combining
    // `(?i)` with `\b` word boundaries forces the regex crate off its fast
    // DFA path into a much slower execution mode — over 1000x slower on real
    // data. Since .onion addresses are base32 (lowercase by convention) and
    // we already call `.to_lowercase()` on matches, case-insensitive matching
    // is unnecessary.
    let onion_re =
        Regex::new(r"\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b")
            .expect("Invalid regex");

    // --- Sequential processing loop ---
    let mut process_count: usize = 0;
    let mut skip_count: usize = 0;
    let mut fail_count: usize = 0;
    let mut new_onions: usize = 0;

    for (i, uri) in uris.iter().enumerate() {
        let filename = match filename_from_uri(uri) {
            Ok(f) => f,
            Err(err) => {
                eprintln!("[{}] {}: {}", i + 1, uri, err);
                continue;
            }
        };

        // --- Check if already processed ---
        if processed.contains(filename) {
            eprintln!("[{}] {} — already processed, skipping", i + 1, filename);
            skip_count += 1;
            continue;
        }

        // --- Enforce processing limit ---
        if process_count >= config.limit {
            eprintln!(
                "Reached processing limit of {}. Stopping.",
                config.limit
            );
            break;
        }

        eprintln!("[{}] {}", i + 1, filename);

        // --- Download if not already on disk ---
        let local_path: PathBuf = Path::new("download").join(filename);
        if !local_path.exists() {
            match download_warc(uri) {
                Ok(_) => {}
                Err(err) => {
                    eprintln!("  [{}] Download error: {}", filename, err);
                    fail_count += 1;
                    eprintln!();
                    continue;
                }
            }
        } else {
            eprintln!("  [{}] Already downloaded", filename);
        }

        // --- Parse the WARC archive ---
        eprintln!("  [{}] Parsing...", filename);
        match parse_warc(&local_path, &onion_re) {
            Ok(onions) => {
                eprintln!("  [{}] Found {} unique .onion address(es)", filename, onions.len());

                let count_before = results.len();
                for onion in onions {
                    let archives = results.entry(onion).or_default();
                    if !archives.contains(&filename.to_string()) {
                        archives.push(filename.to_string());
                    }
                }
                let added = results.len() - count_before;
                new_onions += added;

                // Mark as processed and save results after each archive.
                // If either fails, the next run reprocesses this archive
                // (safe, just redundant).
                if let Err(err) = mark_processed(filename) {
                    eprintln!("  Warning: couldn't mark as processed: {}", err);
                }
                if let Err(err) = save_results(&results) {
                    eprintln!("  Warning: couldn't save results: {}", err);
                }

                process_count += 1;

                // --- Optionally delete the archive ---
                if config.delete {
                    match fs::remove_file(&local_path) {
                        Ok(()) => eprintln!("  [{}] Deleted {}", filename, local_path.display()),
                        Err(err) => eprintln!("  [{}] Warning: couldn't delete: {}", filename, err),
                    }
                }
            }
            Err(err) => {
                eprintln!("  [{}] Parse error: {}", filename, err);
                fail_count += 1;
            }
        }

        eprintln!();
    }

    // --- Final save (safety net) ---
    match save_results(&results) {
        Ok(()) => eprintln!("Results saved to {}", RESULTS_FILE),
        Err(err) => eprintln!("Error saving results: {}", err),
    }

    // --- Summary ---
    eprintln!(
        "\nSummary: {} processed, {} skipped, {} failed, {} new onion(s)",
        process_count, skip_count, fail_count, new_onions
    );
    eprintln!(
        "Total: {} unique .onion address(es) in results",
        results.len()
    );
}
