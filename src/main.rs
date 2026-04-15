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

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use futures::stream::{self, StreamExt};
use regex::Regex;

use onion_crawler::{
    download_warc_async, download_warc_to_memory, filename_from_uri,
    load_favicons_from, load_processed_from, load_results_from,
    mark_processed_in, merge_favicons, merge_results,
    parse_warc, parse_warc_bytes, parse_warc_bytes_from_memory, parse_warc_memchr,
    parse_warc_memchr_from_memory, parse_warc_mmap, save_favicons_to, save_results_to,
    FaviconSource, OnionSource,
    DEFAULT_OUTPUT_DIR, FAVICONS_FILENAME, RESULTS_FILENAME,
};

// ---------------------------------------------------------------------------
// Parsing Strategy Selection
// ---------------------------------------------------------------------------

/// Parsing strategy — selects which optimization layer to use.
///
/// Each strategy produces identical results but uses different techniques,
/// inspired by how ripgrep achieves its speed. Run all four on the same
/// archive to benchmark the impact of each optimization.
///
/// `ValueEnum` derive lets `clap` parse the strategy name from the CLI
/// (e.g., `--strategy memchr`). It auto-generates the list of valid values
/// for `--help` output.
#[derive(Clone, Copy, ValueEnum)]
enum Strategy {
    /// Original: warc crate + regex::Regex on UTF-8 strings
    Baseline,
    /// Custom parser + regex::bytes::Regex on raw &[u8] (no UTF-8 conversion)
    Bytes,
    /// Custom parser + SIMD memmem literal search (no regex engine)
    Memchr,
    /// Decompress → mmap → zero-copy memchr search
    Mmap
}

// ---------------------------------------------------------------------------
// CLI Argument Parsing
// ---------------------------------------------------------------------------

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

/// Query available system memory on macOS.
///
/// ## `std::process::Command` — safe alternative to FFI
///
/// macOS exposes memory info through `sysctl`, a command-line tool that
/// queries kernel parameters. We spawn it as a subprocess and parse its
/// stdout — slower than a direct C call (~1 ms vs ~1 μs) but requires
/// no `unsafe` and no C bindings.
///
/// ## Why free + speculative + purgeable?
///
/// macOS categorizes memory pages into several states. "Free" pages alone
/// underestimate available memory because the OS also maintains:
/// - **Speculative pages**: pre-fetched data that can be discarded instantly
/// - **Purgeable pages**: data marked as reclaimable by applications
///
/// Adding these gives a more realistic estimate of memory available for
/// new allocations, closer to what Activity Monitor reports.
#[cfg(target_os = "macos")]
fn get_available_memory() -> Option<u64> {
    use std::process::Command;

    // Helper: run `sysctl -n <key>` and parse the output as u64.
    // Returns 0 if the key doesn't exist on this macOS version, so
    // optional sysctl keys degrade gracefully.
    fn sysctl_value(key: &str) -> Option<u64> {
        let output = Command::new("sysctl")
            .args(["-n", key])
            .output()
            .ok()?;
        // If the key is unknown, sysctl exits with an error — treat as 0.
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u64>()
            .ok()
    }

    let page_size = sysctl_value("vm.pagesize")?;
    let free_pages = sysctl_value("vm.page_free_count")?;
    // Speculative and purgeable pages are immediately reclaimable.
    // These keys may not exist on all macOS versions — default to 0.
    let speculative = sysctl_value("vm.page_speculative_count").unwrap_or(0);
    let purgeable = sysctl_value("vm.page_purgeable_count").unwrap_or(0);

    Some((free_pages + speculative + purgeable) * page_size)
}

/// Query available system memory on Linux.
///
/// ## `/proc/meminfo` — Linux pseudo-filesystem
///
/// On Linux, kernel state is exposed as text files under `/proc`. These
/// aren't real files — the kernel generates their content on each read.
/// `/proc/meminfo` contains memory statistics, one per line:
///
/// ```text
/// MemTotal:       16384000 kB
/// MemFree:         1234567 kB
/// MemAvailable:    8765432 kB
/// ...
/// ```
///
/// `MemAvailable` is the most accurate measure of "how much memory can new
/// allocations use?" — it accounts for free pages, reclaimable caches, and
/// kernel buffers. This is what `free` and `htop` display. It's more useful
/// than `MemFree`, which excludes cache pages the OS would happily reclaim.
#[cfg(target_os = "linux")]
fn get_available_memory() -> Option<u64> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            // Value is in kB — strip the "kB" suffix and convert to bytes.
            let kb: u64 = rest.trim().trim_end_matches("kB").trim().parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

/// Fallback for unsupported platforms — skip the memory check.
///
/// ## `#[cfg]` — conditional compilation
///
/// Rust's `#[cfg(target_os = "...")]` attribute controls which code is
/// compiled on which platform. Unlike C's `#ifdef`, this is checked by the
/// compiler (not a preprocessor), so typos in target names are caught.
/// The three `get_available_memory()` implementations compile to exactly
/// one function in the final binary — the other two don't exist at all.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn get_available_memory() -> Option<u64> {
    None
}

// Parsed command-line configuration.
//
// Uses `clap` derive — the idiomatic Rust way to define CLI interfaces.
// The `#[derive(Parser)]` macro generates all the argument parsing, validation,
// short flags (`-l`, `-j`, `-d`), and `--help` text from the struct definition.
// Field doc comments (`///`) become the help descriptions automatically.
// We use `//` (not `///`) for these explanatory comments so clap doesn't
// include them in the `--help` output — only `///` on fields becomes help text.
//
// ## Subcommands for HPC / batch mode
//
// The CLI uses subcommands to support two modes:
//   - `run` (default): download + parse archives (the original behavior)
//   - `merge`: combine partial results from parallel SLURM array tasks
//
// `SubcommandRequiredElseHelp` is not used — when no subcommand is given,
// we default to `run` for backwards compatibility. The `input` positional
// argument on the top-level struct is what makes this work: clap sees it
// and treats the invocation as an implicit `run`.
// ## Subcommands for HPC / batch mode
//
// The CLI uses subcommands to support two modes:
//   - default (no subcommand): download + parse archives (the original behavior)
//   - `merge`: combine partial results from parallel SLURM array tasks
//
// The top-level struct keeps all the `run` flags directly so existing
// invocations (`onion-crawler warc.paths -l 3`) continue to work unchanged.
// Only the `merge` subcommand requires an explicit keyword.
#[derive(Parser)]
#[command(name = "onion-crawler")]
#[command(about = "Extract .onion addresses from Common Crawl WARC archives")]
struct Config {
    /// Path to the WARC-paths file (supports .gz) — omit when using `merge`
    input: Option<String>,

    /// Maximum number of archives to process (default: all)
    #[arg(short, long)]
    limit: Option<usize>,

    /// Skip the first N paths in the file (for SLURM array partitioning)
    ///
    /// Combined with --limit, this lets each SLURM array task process a
    /// non-overlapping slice: task 0 gets --offset 0 --limit 1000,
    /// task 1 gets --offset 1000 --limit 1000, etc.
    #[arg(short, long, default_value_t = 0)]
    offset: usize,

    /// Number of concurrent download+parse tasks
    #[arg(short, long, default_value_t = default_jobs())]
    jobs: usize,

    /// Delete archive files after parsing
    #[arg(short, long)]
    delete: bool,

    /// Parsing strategy: baseline, bytes, memchr, or mmap
    #[arg(short, long, value_enum, default_value_t = Strategy::Memchr)]
    strategy: Strategy,

    /// Parse from memory instead of disk (skips file I/O, uses more RAM)
    #[arg(short = 'm', long)]
    stream: bool,

    /// Output directory for results and processed log (default: output/)
    ///
    /// In HPC batch mode, each SLURM task should use a unique directory
    /// (e.g., `--output-dir output/42/`) to avoid file contention.
    #[arg(long, default_value = DEFAULT_OUTPUT_DIR)]
    output_dir: String,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Merge partial results from multiple output directories (HPC post-processing)
    ///
    /// After a SLURM array job completes, each task has written its own
    /// `onions.json` in a separate directory. This subcommand reads them all,
    /// deduplicates, and writes a combined result.
    Merge {
        /// Directories containing partial onions.json files to merge
        #[arg(required = true)]
        input_dirs: Vec<PathBuf>,

        /// Output directory for the merged result (default: output/)
        #[arg(short, long, default_value = DEFAULT_OUTPUT_DIR)]
        output_dir: String,
    },
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
    onions: HashMap<String, Vec<OnionSource>>,
    favicon_urls: HashMap<String, Vec<FaviconSource>>,
    download_time: Duration,
    parse_time: Duration
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
    // `Config::parse()` is generated by the `clap` derive macro. It reads
    // `std::env::args()`, validates types, and exits with a help message
    // if required arguments are missing or `--help` is passed.
    let config = Config::parse();

    // --- Dispatch: merge subcommand or default crawl pipeline ---
    if let Some(Command::Merge { input_dirs, output_dir }) = config.command {
        run_merge(&input_dirs, &output_dir);
        return;
    }

    // Default mode: require the input paths file
    let input = match config.input {
        Some(ref path) => path.clone(),
        None => {
            eprintln!("Error: missing required argument <INPUT> (path to WARC-paths file)");
            eprintln!("Usage: onion-crawler <INPUT> [OPTIONS]");
            eprintln!("       onion-crawler merge <INPUT_DIRS>...");
            process::exit(1);
        }
    };

    run_crawl(input, config).await;
}

/// Merge partial results from multiple SLURM task output directories.
fn run_merge(input_dirs: &[PathBuf], output_dir: &str) {
    eprintln!(
        "Merging results from {} directories into '{}'",
        input_dirs.len(),
        output_dir
    );

    let merged_onions = merge_results(input_dirs);
    let merged_favicons = merge_favicons(input_dirs);

    eprintln!(
        "Merged: {} unique .onion address(es), {} unique favicon URL(s)",
        merged_onions.len(),
        merged_favicons.len()
    );

    match save_results_to(&merged_onions, output_dir) {
        Ok(()) => {
            let path = Path::new(output_dir).join(RESULTS_FILENAME);
            eprintln!("Onion results saved to {}", path.display());
        }
        Err(err) => {
            eprintln!("Error saving merged onion results: {}", err);
            process::exit(1);
        }
    }

    match save_favicons_to(&merged_favicons, output_dir) {
        Ok(()) => {
            let path = Path::new(output_dir).join(FAVICONS_FILENAME);
            eprintln!("Favicon results saved to {}", path.display());
        }
        Err(err) => {
            eprintln!("Error saving merged favicon results: {}", err);
            process::exit(1);
        }
    }
}

/// Main crawl pipeline — download and parse WARC archives.
async fn run_crawl(input: String, config: Config) {
    let limit_display = match config.limit {
        Some(n) => format!("{}", n),
        None => "all".to_string()
    };
    let strategy_name = match config.strategy {
        Strategy::Baseline => "baseline (warc crate + regex)",
        Strategy::Bytes => "bytes (custom parser + regex::bytes)",
        Strategy::Memchr => "memchr (custom parser + SIMD memmem)",
        Strategy::Mmap => "mmap (decompress + mmap + SIMD memmem)"
    };

    // --- Check stream mode compatibility ---
    //
    // ## Graceful degradation
    //
    // Not all strategies support in-memory parsing. Rather than erroring
    // out, we warn the user and fall back to disk mode. This is a common
    // CLI UX pattern: prefer doing the right thing with a warning over
    // refusing to run.
    let stream_enabled = if config.stream {
        match config.strategy {
            Strategy::Baseline => {
                eprintln!(
                    "Warning: --stream is not compatible with 'baseline' strategy \
                     (warc crate requires a file path). Falling back to disk mode."
                );
                false
            }
            Strategy::Mmap => {
                eprintln!(
                    "Warning: --stream is not compatible with 'mmap' strategy \
                     (memory mapping requires a file). Falling back to disk mode."
                );
                false
            }
            Strategy::Bytes | Strategy::Memchr => true,
        }
    } else {
        false
    };

    // --- Cap jobs at 2× CPU cores ---
    //
    // Each job runs CPU-bound parsing via `spawn_blocking` (gzip decompression
    // + search). More jobs than available threads means tasks queue up waiting
    // for a blocking thread, adding context switching overhead without any
    // throughput gain. We allow 2× cores to keep the pipeline full: while N
    // archives are parsing, up to N more can be downloading (async, lightweight).
    let cpu_cores = default_jobs();
    let max_cpu_jobs = cpu_cores * 2;
    let capped_jobs = if config.jobs > max_cpu_jobs {
        eprintln!(
            "Warning: {} jobs requested but only {} CPU cores detected. \
             Capping to {} (2\u{00d7} cores) to avoid oversubscription.",
            config.jobs, cpu_cores, max_cpu_jobs,
        );
        max_cpu_jobs
    } else {
        config.jobs
    };

    // --- Cap concurrent jobs based on available RAM (stream mode only) ---
    //
    // ## Defensive resource management
    //
    // In stream mode, each concurrent job holds an entire archive in memory
    // (~800 MB–1 GB). Without a cap, a 16-core machine with 8 GB of RAM
    // would try to hold 16 archives simultaneously — guaranteed OOM.
    //
    // We query available RAM once at startup and compute the maximum safe
    // number of concurrent stream jobs. `buffer_unordered` then provides
    // natural backpressure: when a job finishes and frees its buffer, the
    // next one starts and allocates a new buffer.
    let effective_jobs = if stream_enabled {
        const MAX_ARCHIVE_SIZE: u64 = 1_073_741_824; // 1 GB worst case
        if let Some(available) = get_available_memory() {
            let max_jobs = (available / MAX_ARCHIVE_SIZE).max(1) as usize;
            if max_jobs < capped_jobs {
                eprintln!(
                    "Warning: available RAM ({:.1} GB) limits stream jobs to {} \
                     (requested {}). Use disk mode or free memory for more concurrency.",
                    available as f64 / 1_073_741_824.0,
                    max_jobs,
                    capped_jobs,
                );
                max_jobs
            } else {
                capped_jobs
            }
        } else {
            capped_jobs // Can't detect RAM — proceed with CPU-capped jobs
        }
    } else {
        capped_jobs // Disk mode — no memory concern
    };

    let offset_display = if config.offset > 0 {
        format!(", offset: {}", config.offset)
    } else {
        String::new()
    };
    let output_dir_display = if config.output_dir != DEFAULT_OUTPUT_DIR {
        format!(", output: {}", config.output_dir)
    } else {
        String::new()
    };
    eprintln!(
        "Reading WARC paths from '{}' (limit: {}{}, jobs: {}, delete after: {}, strategy: {}, stream: {}{})",
        input, limit_display, offset_display, effective_jobs,
        config.delete, strategy_name, stream_enabled, output_dir_display
    );

    // --- Open and read the paths file ---
    // Supports both plain text and gzip-compressed (.gz) paths files.
    // Common Crawl distributes warc.paths.gz — we decompress transparently
    // using `libflate`, which is already in the dependency tree via the `warc` crate.
    let file = File::open(&input).unwrap_or_else(|err| {
        eprintln!("Error: cannot open '{}': {}", input, err);
        process::exit(1);
    });

    let reader: Box<dyn BufRead> = if input.ends_with(".gz") {
        let decoder = libflate::gzip::Decoder::new(file).unwrap_or_else(|err| {
            eprintln!(
                "Error: failed to decompress '{}': {}",
                input, err
            );
            process::exit(1);
        });
        Box::new(BufReader::new(decoder))
    } else {
        Box::new(BufReader::new(file))
    };

    let uris: Vec<String> = reader
        .lines()
        .filter_map(Result::ok)
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .skip(config.offset)
        .collect();

    if uris.is_empty() {
        eprintln!("No paths found in '{}' (after offset {})", input, config.offset);
        process::exit(1);
    }

    eprintln!(
        "Found {} path(s) in file{}",
        uris.len(),
        if config.offset > 0 { format!(" (after skipping {})", config.offset) } else { String::new() }
    );

    // --- Load persistent state ---
    let processed = load_processed_from(&config.output_dir);
    let mut results = load_results_from(&config.output_dir);
    let mut favicon_results = load_favicons_from(&config.output_dir);

    eprintln!(
        "State: {} already processed, {} onion(s), {} favicon URL(s) in results\n",
        processed.len(),
        results.len(),
        favicon_results.len()
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

        if let Some(limit) = config.limit {
            if work_items.len() >= limit {
                eprintln!("Reached processing limit of {}. Stopping.", limit);
                break;
            }
        }

        work_items.push((i + 1, uri.clone()));
    }

    let output_dir = config.output_dir;

    if work_items.is_empty() {
        eprintln!("No archives to process.");
        match save_results_to(&results, &output_dir) {
            Ok(()) => {
                let path = Path::new(&output_dir).join(RESULTS_FILENAME);
                eprintln!("Results saved to {}", path.display());
            }
            Err(err) => eprintln!("Error saving results: {}", err)
        }
        match save_favicons_to(&favicon_results, &output_dir) {
            Ok(()) => {
                let path = Path::new(&output_dir).join(FAVICONS_FILENAME);
                eprintln!("Favicons saved to {}", path.display());
            }
            Err(err) => eprintln!("Error saving favicons: {}", err)
        }
        eprintln!(
            "\nSummary: 0 processed, {} skipped, 0 failed, 0 new onion(s), 0 new favicon URL(s)",
            skip_count
        );
        eprintln!(
            "Total: {} unique .onion address(es), {} unique favicon URL(s) in results",
            results.len(),
            favicon_results.len()
        );
        return;
    }

    eprintln!("Processing {} archive(s) with {} concurrent job(s)\n", work_items.len(), effective_jobs);

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
    //
    // Only the Baseline strategy uses this regex — the others use either
    // `regex::bytes::Regex` (compiled per-call) or `memmem::Finder`.
    // We still compile it unconditionally to keep the code simple.
    let onion_re = Arc::new(
        Regex::new(r"\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b")
            .expect("Invalid regex")
    );

    let strategy = config.strategy;

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

                // --- Download phase ---
                //
                // In stream mode, we download to memory (`Vec<u8>`) instead
                // of disk. The compressed bytes stay in RAM and are passed
                // directly to the parser. In disk mode, we write to
                // `download/<filename>` as before.
                let local_path: PathBuf = Path::new("download").join(&filename);
                let download_start = Instant::now();

                // `Option<Vec<u8>>` holds the in-memory buffer in stream mode.
                // In disk mode, this stays `None` and the parser reads from disk.
                let memory_buffer: Option<Vec<u8>> = if stream_enabled {
                    match download_warc_to_memory(&client, &uri).await {
                        Ok(buf) => Some(buf),
                        Err(err) => {
                            eprintln!("  [{}] Download error: {}", filename, err);
                            return Err(format!("{}: download error: {}", filename, err));
                        }
                    }
                } else {
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
                    None
                };

                let download_time = download_start.elapsed();
                eprintln!("  [{}] Download time: {:.1}s", filename, download_time.as_secs_f64());

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
                // In stream mode, the `Vec<u8>` buffer is *moved* into the
                // blocking closure — this is a zero-cost ownership transfer
                // (no data copying). After the move, the async task no longer
                // owns the buffer, and the compiler prevents use-after-move.
                let strategy_label = match strategy {
                    Strategy::Baseline => "baseline",
                    Strategy::Bytes => if stream_enabled { "bytes/stream" } else { "bytes" },
                    Strategy::Memchr => if stream_enabled { "memchr/stream" } else { "memchr" },
                    Strategy::Mmap => "mmap"
                };
                eprintln!("  [{}] Parsing ({})...", filename, strategy_label);
                let parse_path = local_path.clone();
                let parse_re = Arc::clone(&onion_re);
                let parse_filename = filename.clone();

                let parse_start = Instant::now();
                let parse_result = tokio::task::spawn_blocking(move || {
                    match (strategy, memory_buffer) {
                        // Stream mode: parse from in-memory buffer
                        (Strategy::Bytes, Some(data)) => {
                            parse_warc_bytes_from_memory(data, &parse_filename)
                        }
                        (Strategy::Memchr, Some(data)) => {
                            parse_warc_memchr_from_memory(data, &parse_filename)
                        }
                        // Disk mode: parse from file (existing behavior)
                        (Strategy::Baseline, _) => parse_warc(&parse_path, &parse_re),
                        (Strategy::Bytes, None) => parse_warc_bytes(&parse_path),
                        (Strategy::Memchr, None) => parse_warc_memchr(&parse_path),
                        (Strategy::Mmap, _) => parse_warc_mmap(&parse_path)
                    }
                })
                .await;
                let parse_time = parse_start.elapsed();

                // `spawn_blocking` returns a `JoinHandle` — unwrap the
                // outer Result (task panic) then the inner Result (parse error).
                let parsed = match parse_result {
                    Ok(Ok(result)) => result,
                    Ok(Err(err)) => {
                        eprintln!("  [{}] Parse error: {}", filename, err);
                        return Err(format!("{}: parse error: {}", filename, err));
                    }
                    Err(err) => {
                        eprintln!("  [{}] Task panic: {}", filename, err);
                        return Err(format!("{}: task panic: {}", filename, err));
                    }
                };

                eprintln!("  [{}] Parsing time: {:.1}s", filename, parse_time.as_secs_f64());
                eprintln!(
                    "  [{}] Found {} unique .onion address(es), {} favicon URL(s)",
                    filename, parsed.onions.len(), parsed.favicon_urls.len()
                );

                Ok((idx, filename, local_path, ArchiveResult {
                    onions: parsed.onions,
                    favicon_urls: parsed.favicon_urls,
                    download_time,
                    parse_time
                }))
            }
        })
        .buffer_unordered(effective_jobs);

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
    let mut new_favicons: usize = 0;
    let mut total_download = Duration::ZERO;
    let mut total_parse = Duration::ZERO;

    // `pin_mut!` pins the stream to the stack so we can poll it.
    // This is needed because `buffer_unordered` returns a stream that
    // must be pinned to be polled (a Rust async trait requirement).
    futures::pin_mut!(archive_stream);

    while let Some(task_result) = archive_stream.next().await {
        match task_result {
            Ok((_idx, filename, local_path, archive)) => {
                total_download += archive.download_time;
                total_parse += archive.parse_time;

                // Merge onion results
                let count_before = results.len();
                for (onion, sources) in archive.onions {
                    let existing = results.entry(onion).or_default();
                    for source in sources {
                        if !existing.iter().any(|s| s.url == source.url && s.archive == source.archive) {
                            existing.push(source);
                        }
                    }
                }
                new_onions += results.len() - count_before;

                // Merge favicon results
                let fav_count_before = favicon_results.len();
                for (url, sources) in archive.favicon_urls {
                    let existing = favicon_results.entry(url).or_default();
                    for source in sources {
                        if !existing.iter().any(|s| s.page_url == source.page_url && s.archive == source.archive) {
                            existing.push(source);
                        }
                    }
                }
                new_favicons += favicon_results.len() - fav_count_before;

                if let Err(err) = mark_processed_in(&filename, &output_dir) {
                    eprintln!("  Warning: couldn't mark as processed: {}", err);
                }
                if let Err(err) = save_results_to(&results, &output_dir) {
                    eprintln!("  Warning: couldn't save results: {}", err);
                }
                if let Err(err) = save_favicons_to(&favicon_results, &output_dir) {
                    eprintln!("  Warning: couldn't save favicons: {}", err);
                }

                process_count += 1;

                // In stream mode there is no local file to delete — the
                // data was parsed from memory and already dropped.
                if delete && !stream_enabled {
                    match fs::remove_file(&local_path) {
                        Ok(()) => eprintln!("  [{}] Deleted {}", filename, local_path.display()),
                        Err(err) => eprintln!("  [{}] Warning: couldn't delete: {}", filename, err)
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
    match save_results_to(&results, &output_dir) {
        Ok(()) => {
            let path = Path::new(&output_dir).join(RESULTS_FILENAME);
            eprintln!("Results saved to {}", path.display());
        }
        Err(err) => eprintln!("Error saving results: {}", err)
    }
    match save_favicons_to(&favicon_results, &output_dir) {
        Ok(()) => {
            let path = Path::new(&output_dir).join(FAVICONS_FILENAME);
            eprintln!("Favicons saved to {}", path.display());
        }
        Err(err) => eprintln!("Error saving favicons: {}", err)
    }

    // --- Summary ---
    eprintln!(
        "\nSummary: {} processed, {} skipped, {} failed, {} new onion(s), {} new favicon URL(s)",
        process_count, skip_count, fail_count, new_onions, new_favicons
    );
    eprintln!(
        "Total: {} unique .onion address(es), {} unique favicon URL(s) in results",
        results.len(),
        favicon_results.len()
    );
    if process_count > 0 {
        let avg_dl = total_download.as_secs_f64() / process_count as f64;
        let avg_parse = total_parse.as_secs_f64() / process_count as f64;
        eprintln!(
            "Avg per archive: {:.1}s download, {:.1}s parsing",
            avg_dl, avg_parse
        );
    }
}
