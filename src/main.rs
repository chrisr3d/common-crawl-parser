// onion-crawler — Step 6: Concurrent downloads & processing with Tokio
//
// Building on Step 5, the pipeline now runs concurrently:
//   - Multiple archives download in parallel (async I/O with reqwest)
//   - Parsing starts as soon as each download completes (pipeline)
//   - CPU-bound WARC parsing runs on Tokio's blocking thread pool
//
// The key insight: I/O-bound work (downloads) benefits from async because the
// thread is released during network waits. CPU-bound work (parsing) still needs
// real threads — `spawn_blocking` bridges the two worlds.
//
// New concepts: async/await, Tokio runtime, reqwest streaming, spawn_blocking,
// bounded concurrency with buffer_unordered, Arc for shared ownership.

use std::collections::{HashMap, HashSet};
use std::env;
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;

use futures::stream::{self, StreamExt};
use regex::Regex;
use warc::{RecordType, WarcReader};

/// Base URL for Common Crawl data archives.
const COMMONCRAWL_BASE: &str = "https://data.commoncrawl.org/";


/// Detect the number of CPU cores available for parallel work.
///
/// `available_parallelism()` queries the OS for the number of logical CPUs
/// (hardware threads). This is the right default for our workload: each job
/// does CPU-bound parsing (gzip decompression + regex) via `spawn_blocking`,
/// so one job per core avoids oversubscription. Falls back to 1 if detection
/// fails (e.g. in constrained containers).
fn default_jobs() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// File tracking which archives have been fully processed.
const PROCESSED_FILE: &str = "output/processed.log";

/// JSON file storing extracted .onion addresses and their source archives.
const RESULTS_FILE: &str = "output/onions.json";

// ---------------------------------------------------------------------------
// CLI Argument Parsing
// ---------------------------------------------------------------------------

/// Parsed command-line configuration.
///
/// The `jobs` field controls download concurrency — how many archives to
/// download simultaneously. This is important because:
/// - Too few jobs underutilizes network bandwidth (sequential bottleneck)
/// - Too many jobs can overwhelm the server or local resources
/// - Default matches CPU core count (scales to the machine)
struct Config {
    paths_file: String,
    limit: usize,
    delete: bool,
    /// Number of concurrent download+parse tasks.
    jobs: usize,
}

/// Parse command-line arguments into a `Config`.
///
/// Supports:
///   --limit N / --limit=N  → cap how many archives to process (default: all)
///   --jobs N / --jobs=N    → concurrent download tasks (default: CPU cores)
///   --delete               → remove archive files after parsing
///   <positional>           → path to the WARC-paths file
fn parse_args() -> Config {
    let args: Vec<String> = env::args().skip(1).collect();

    let mut paths_file = String::from("warc.paths");
    let mut limit: usize = 0;
    let mut delete = false;
    let mut jobs = default_jobs();

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
        } else if let Some(value) = args[i].strip_prefix("--jobs=") {
            jobs = value.parse::<usize>().unwrap_or_else(|_| {
                eprintln!("Error: --jobs value '{}' is not a valid number", value);
                process::exit(1);
            });
        } else if args[i] == "--jobs" {
            i += 1;
            if i >= args.len() {
                eprintln!("Error: --jobs requires a value");
                process::exit(1);
            }
            jobs = args[i].parse::<usize>().unwrap_or_else(|_| {
                eprintln!("Error: --jobs value '{}' is not a valid number", args[i]);
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

    // Ensure jobs is at least 1 — zero concurrency would deadlock.
    if jobs == 0 {
        jobs = 1;
    }

    Config {
        paths_file,
        limit,
        delete,
        jobs,
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

/// Download a single WARC archive from Common Crawl using async I/O.
///
/// ## Why `reqwest` instead of `ureq`
///
/// `ureq` is a blocking HTTP client — while waiting for network data, the
/// thread sits idle. This is fine for sequential code but wasteful when we
/// want concurrency: each concurrent download would need its own OS thread.
///
/// `reqwest` is async-native: it uses Tokio's I/O driver so the thread is
/// released during network waits and can run other tasks. With 4 concurrent
/// downloads, we use ~1 thread instead of 4 blocked threads. This is the
/// core benefit of async for I/O-bound work.
///
/// ## Streaming download
///
/// We use `response.chunk()` to stream the body in pieces rather than
/// buffering the entire archive (hundreds of MB) in memory. Each chunk is
/// written to disk immediately. This keeps memory usage constant regardless
/// of archive size.
async fn download_warc_async(
    client: &reqwest::Client,
    uri: &str,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let url = format!("{}{}", COMMONCRAWL_BASE, uri);
    let filename = filename_from_uri(uri).map_err(|e| -> Box<dyn Error + Send + Sync> {
        e.into()
    })?;
    let local_path: PathBuf = Path::new("download").join(filename);

    if local_path.exists() {
        eprintln!("  [{}] Already downloaded, skipping download", filename);
        return Ok(false);
    }

    // `tokio::fs::create_dir_all` is the async version of `fs::create_dir_all`.
    // For file system operations, async doesn't help much (disk I/O is fast),
    // but it avoids blocking the Tokio runtime thread.
    tokio::fs::create_dir_all("download").await?;

    eprintln!("  [{}] Downloading...", filename);
    eprintln!("  [{}] URL: {}", filename, url);

    let mut response = client.get(&url).send().await?.error_for_status()?;

    // Content-Length header tells us the total size (if the server provides it).
    let total_size = response.content_length();
    if let Some(size) = total_size {
        eprintln!("  [{}] Size: {:.1} MB", filename, size as f64 / 1_048_576.0);
    }

    // Stream the response body chunk by chunk to a file.
    // `response.chunk()` yields `Option<Bytes>` — each call returns the next
    // piece of the body, or None when complete. At each `.await`, the task
    // suspends and the thread can run other downloads.
    let mut file = tokio::fs::File::create(&local_path).await?;
    let mut bytes_written: u64 = 0;
    let mut last_report: u64 = 0;

    // `bytes_stream()` returns a Stream of Result<Bytes> chunks.
    // We consume it with `while let` + `.chunk()` for simplicity.
    while let Some(chunk) = response.chunk().await? {
        tokio::io::AsyncWriteExt::write_all(&mut file, &chunk).await?;
        bytes_written += chunk.len() as u64;

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
/// This function is **synchronous** — the `warc` crate uses blocking I/O
/// internally (decompressing gzip, reading record boundaries). We don't
/// rewrite it as async because:
///
/// 1. The `warc` crate doesn't support async — we'd need a different library
/// 2. Parsing is CPU-bound (decompression + regex matching), not I/O-bound
/// 3. Async shines for I/O waits (network, slow disk); for CPU work it just
///    adds overhead
///
/// Instead, we call this from `spawn_blocking` (see the pipeline in `main`),
/// which runs it on Tokio's dedicated blocking thread pool. This is the
/// idiomatic way to mix sync CPU work with async I/O in Tokio.
fn parse_warc(path: &Path, onion_re: &Regex) -> Result<HashSet<String>, Box<dyn Error + Send + Sync>> {
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
// Per-archive task result
// ---------------------------------------------------------------------------

/// The outcome of processing a single archive — passed back from each
/// concurrent task to the main task for merging.
///
/// We need this struct because each task runs independently and can't
/// mutate shared state. Instead, each task returns its results and the
/// main task merges them sequentially — no locks needed.
struct ArchiveResult {
    onions: HashSet<String>,
}

// ---------------------------------------------------------------------------
// Main — async entry point
// ---------------------------------------------------------------------------

/// ## `#[tokio::main]` — the async runtime entry point
///
/// Rust's `main` must be synchronous, but we need an async runtime to drive
/// our concurrent downloads. `#[tokio::main]` is a macro that:
/// 1. Creates a multi-threaded Tokio runtime (default: one thread per CPU core)
/// 2. Runs our `async fn main()` on that runtime
/// 3. Shuts down the runtime when `main` completes
///
/// This is equivalent to writing:
/// ```
/// fn main() {
///     tokio::runtime::Runtime::new().unwrap().block_on(async { ... })
/// }
/// ```
/// The macro is just more concise.
#[tokio::main]
async fn main() {
    // --- Parse CLI arguments (synchronous — runs before the async work) ---
    let config = parse_args();

    let limit_display = if config.limit > 0 {
        format!("{}", config.limit)
    } else {
        "all".to_string()
    };
    eprintln!(
        "Reading WARC paths from '{}' (limit: {}, jobs: {}, delete after: {})",
        config.paths_file, limit_display, config.jobs, config.delete
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

    // --- Filter URIs: skip already-processed, apply limit ---
    // We do this upfront so we know exactly which archives to process
    // concurrently. Skipped archives are logged but don't count toward
    // the limit.
    let mut work_items: Vec<(usize, String)> = Vec::new();
    let mut skip_count: usize = 0;

    for (i, uri) in uris.iter().enumerate() {
        let filename = match filename_from_uri(uri) {
            Ok(f) => f,
            Err(err) => {
                eprintln!("[{}] {}: {}", i + 1, uri, err);
                continue;
            }
        };

        if processed.contains(filename) {
            eprintln!("[{}] {} — already processed, skipping", i + 1, filename);
            skip_count += 1;
            continue;
        }

        if config.limit > 0 && work_items.len() >= config.limit {
            eprintln!(
                "Reached processing limit of {}. Stopping.",
                config.limit
            );
            break;
        }

        work_items.push((i + 1, uri.clone()));
    }

    if work_items.is_empty() {
        eprintln!("No archives to process.");
        // Still save results (safety net) and print summary.
        match save_results(&results) {
            Ok(()) => eprintln!("Results saved to {}", RESULTS_FILE),
            Err(err) => eprintln!("Error saving results: {}", err),
        }
        eprintln!(
            "\nSummary: 0 processed, {} skipped, 0 failed, 0 new onion(s)",
            skip_count
        );
        eprintln!(
            "Total: {} unique .onion address(es) in results",
            results.len()
        );
        return;
    }

    eprintln!("Processing {} archive(s) with {} concurrent job(s)\n", work_items.len(), config.jobs);

    // --- Compile the .onion regex once, wrapped in Arc for sharing ---
    //
    // ## `Arc` — atomic reference counting for shared ownership
    //
    // Each concurrent task needs access to the compiled regex. We can't
    // pass a `&Regex` reference because async tasks may outlive the current
    // scope (Tokio needs `'static` lifetimes for spawned tasks).
    //
    // `Arc` (Atomic Reference Count) solves this: it's a thread-safe smart
    // pointer that keeps the inner value alive as long as any clone exists.
    // Cloning an `Arc` just increments a counter — the regex itself is
    // never copied. This is Rust's standard pattern for sharing immutable
    // data across threads.
    let onion_re = Arc::new(
        Regex::new(r"\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b")
            .expect("Invalid regex"),
    );

    // --- Create a shared HTTP client ---
    //
    // `reqwest::Client` maintains a connection pool internally. Sharing one
    // client across all tasks lets them reuse TCP connections to the same
    // server (HTTP keep-alive), which is faster than each task opening its
    // own connection.
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("Failed to build HTTP client");

    let delete = config.delete;

    // --- Concurrent pipeline with `buffer_unordered` ---
    //
    // ## How the pipeline works
    //
    // `stream::iter(work_items)` creates a stream of (index, uri) pairs.
    // `.map(|item| async { ... })` transforms each into a future that
    // downloads + parses one archive.
    //
    // `.buffer_unordered(jobs)` is the concurrency controller:
    // - It polls up to `jobs` futures simultaneously
    // - Results are yielded as soon as any future completes (not in order)
    // - When one completes, the next pending future starts
    //
    // This gives us bounded concurrency without manual semaphore management.
    // "Unordered" means faster archives finish first — we don't block
    // waiting for a slow download just because it started earlier.
    let archive_stream = stream::iter(work_items)
        .map(|(idx, uri)| {
            // Clone shared resources for this task. `Arc::clone` is cheap
            // (just increments a reference count).
            let client = client.clone();
            let onion_re = Arc::clone(&onion_re);

            async move {
                let filename = match filename_from_uri(&uri) {
                    Ok(f) => f.to_string(),
                    Err(err) => {
                        eprintln!("[{}] {}: {}", idx, uri, err);
                        return Err(format!("{}: {}", uri, err));
                    }
                };

                eprintln!("[{}] {}", idx, filename);

                // --- Download if not already on disk ---
                let local_path: PathBuf = Path::new("download").join(&filename);
                if !local_path.exists() {
                    match download_warc_async(&client, &uri).await {
                        Ok(_) => {}
                        Err(err) => {
                            eprintln!("  [{}] Download error: {}", filename, err);
                            return Err(format!("{}: download error: {}", filename, err));
                        }
                    }
                } else {
                    eprintln!("  [{}] Already downloaded", filename);
                }

                // --- Parse on the blocking thread pool ---
                //
                // ## `spawn_blocking` — bridging sync and async
                //
                // `parse_warc` is CPU-bound (gzip decompression + regex).
                // Running it directly on an async task would block the Tokio
                // worker thread, starving other async tasks (downloads).
                //
                // `spawn_blocking` moves the work to Tokio's dedicated
                // blocking thread pool, which has many more threads and
                // expects blocking work. The `.await` here suspends the
                // async task until the blocking work finishes, freeing the
                // worker thread for other downloads.
                //
                // Rule of thumb: if a function does CPU work or calls
                // blocking I/O for more than a few microseconds, use
                // `spawn_blocking`.
                eprintln!("  [{}] Parsing...", filename);
                let parse_path = local_path.clone();
                let parse_re = Arc::clone(&onion_re);

                let parse_result = tokio::task::spawn_blocking(move || {
                    parse_warc(&parse_path, &parse_re)
                })
                .await;

                // `spawn_blocking` returns a `JoinHandle` — unwrap the
                // outer Result (task panic) then the inner Result (parse error).
                let onions = match parse_result {
                    Ok(Ok(onions)) => onions,
                    Ok(Err(err)) => {
                        eprintln!("  [{}] Parse error: {}", filename, err);
                        return Err(format!("{}: parse error: {}", filename, err));
                    }
                    Err(err) => {
                        eprintln!("  [{}] Task panic: {}", filename, err);
                        return Err(format!("{}: task panic: {}", filename, err));
                    }
                };

                eprintln!("  [{}] Found {} unique .onion address(es)", filename, onions.len());

                Ok((idx, filename, local_path, ArchiveResult { onions }))
            }
        })
        .buffer_unordered(config.jobs);

    // --- Collect results back on the main task ---
    //
    // `buffer_unordered` yields results as futures complete. We process
    // them sequentially here: merge onions into the shared results map,
    // mark archives as processed, and optionally delete files.
    //
    // This is a key design choice: concurrent *work*, sequential *merging*.
    // No locks, no race conditions — the simplest correct approach.
    let mut process_count: usize = 0;
    let mut fail_count: usize = 0;
    let mut new_onions: usize = 0;

    // `pin_mut!` pins the stream to the stack so we can poll it.
    // This is needed because `buffer_unordered` returns a stream that
    // must be pinned to be polled (a Rust async trait requirement).
    futures::pin_mut!(archive_stream);

    while let Some(task_result) = archive_stream.next().await {
        match task_result {
            Ok((_idx, filename, local_path, archive)) => {
                let count_before = results.len();
                for onion in archive.onions {
                    let archives = results.entry(onion).or_default();
                    if !archives.contains(&filename) {
                        archives.push(filename.clone());
                    }
                }
                let added = results.len() - count_before;
                new_onions += added;

                if let Err(err) = mark_processed(&filename) {
                    eprintln!("  Warning: couldn't mark as processed: {}", err);
                }
                if let Err(err) = save_results(&results) {
                    eprintln!("  Warning: couldn't save results: {}", err);
                }

                process_count += 1;

                if delete {
                    match fs::remove_file(&local_path) {
                        Ok(()) => eprintln!("  [{}] Deleted {}", filename, local_path.display()),
                        Err(err) => eprintln!("  [{}] Warning: couldn't delete: {}", filename, err),
                    }
                }

                eprintln!();
            }
            Err(err) => {
                eprintln!("  Error: {}", err);
                fail_count += 1;
                eprintln!();
            }
        }
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
