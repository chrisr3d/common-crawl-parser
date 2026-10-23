// cc-extract — Step 6: Concurrent downloads & processing with Tokio
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

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use futures::stream::{self, StreamExt};

use cc_extract::{
    download_warc_async, download_warc_to_memory, filename_from_uri, load_processed_from,
    load_sightings_from, merge_sightings, merge_sightings_from, parse_archive, save_sightings_to,
    save_then_mark, ArtifactKind, Extractor, FaviconExtractor, OnionEngine, OnionExtractor,
    Shard, Sightings, Transport, DEFAULT_OUTPUT_DIR,
};

// ---------------------------------------------------------------------------
// Transport and extractor selection
// ---------------------------------------------------------------------------

/// How downloaded Archives reach the parser, as chosen with `--transport`.
///
/// The library's `Transport` can't be parsed from the command line
/// directly: its variants carry the file path or the downloaded bytes,
/// which only exist once an Archive is downloaded. This fieldless enum is
/// the choice alone; each task turns it into a `Transport` (see
/// `run_crawl`). All three give identical results; run them on the same
/// Archive to compare their speed.
///
/// `ValueEnum` derive lets `clap` parse the name from the CLI (e.g.,
/// `--transport memory`). It auto-generates the list of valid values for
/// `--help` output, with each variant's doc comment as its description.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TransportChoice {
    /// Download to download/, stream-decompress from the file
    Disk,
    /// Download into RAM, stream-decompress from there (no disk I/O, ~1 GB per job)
    Memory,
    /// Download to download/, decompress to a temporary .warc, memory-map it
    Mmap,
}

/// The extractor for one Artifact kind, set up from the CLI options.
///
/// The one place a kind is matched to its `Extractor`: a new kind makes
/// this `match` non-exhaustive, so the compiler points here.
fn new_extractor(kind: ArtifactKind, onion_engine: OnionEngine) -> Box<dyn Extractor> {
    match kind {
        ArtifactKind::Onion => Box::new(OnionExtractor::new(onion_engine)),
        ArtifactKind::Favicon => Box::new(FaviconExtractor::new()),
    }
}

/// The name `clap` accepts for `value`, for messages (`memory`, `regex`).
fn cli_name(value: &impl ValueEnum) -> String {
    value
        .to_possible_value()
        .expect("no CLI value is skipped")
        .get_name()
        .to_string()
}

/// `onion,favicon`: kinds as written for `--extract`.
fn kind_list(kinds: &[ArtifactKind]) -> String {
    let names: Vec<String> = kinds.iter().map(ToString::to_string).collect();
    names.join(",")
}

/// `2 onion(s), 5 favicon(s)`: one count per kind.
fn count_list(counts: impl IntoIterator<Item = (ArtifactKind, usize)>) -> String {
    let counts: Vec<String> = counts
        .into_iter()
        .map(|(kind, count)| format!("{} {}(s)", count, kind))
        .collect();
    counts.join(", ")
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
//   - default (no subcommand): download + parse archives (the original behavior)
//   - `merge`: combine partial results from parallel SLURM array tasks
//
// The top-level struct keeps all the `run` flags directly so existing
// invocations (`cc-extract warc.paths -l 3`) work without a keyword.
// Only the `merge` subcommand requires an explicit keyword.
#[derive(Parser)]
#[command(name = "cc-extract")]
#[command(about = "Extract artifacts, such as .onion addresses and favicon URLs, from Common Crawl archives")]
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

    /// Artifact kinds to extract, comma-separated
    ///
    /// A Shard is processed again only for the kinds not yet done for it
    /// in `processed.log`, so a kind can be added in a later run.
    //
    // ## Comma-delimited lists
    //
    // `Vec<ArtifactKind>` makes the option take several values;
    // `value_delimiter = ','` splits `-e onion,favicon` into two, each
    // parsed through `ArtifactKind`'s `ValueEnum` derive. The default is
    // written as the user would type it and split the same way, so
    // `--help` shows `[default: onion,favicon]`.
    #[arg(short, long, value_enum, value_delimiter = ',', default_value = "onion,favicon")]
    extract: Vec<ArtifactKind>,

    /// How downloaded archives reach the parser
    #[arg(short, long, value_enum, default_value_t = TransportChoice::Disk)]
    transport: TransportChoice,

    /// Search used to find .onion addresses
    #[arg(long, value_enum, default_value_t = OnionEngine::Memchr)]
    onion_engine: OnionEngine,

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
    /// results files in a separate directory. This subcommand reads them
    /// all, deduplicates, and writes one combined file per Artifact kind.
    Merge {
        /// Directories containing partial results files to merge
        #[arg(required = true)]
        input_dirs: Vec<PathBuf>,

        /// Output directory for the merged result (default: output/)
        #[arg(short, long, default_value = DEFAULT_OUTPUT_DIR)]
        output_dir: String,
    },
}

// ---------------------------------------------------------------------------
// Per-archive task input and result
// ---------------------------------------------------------------------------

/// One Archive to process, and the requested kinds not yet done for its
/// Shard. Only those kinds' extractors run on it.
struct ScheduledArchive {
    /// 1-based position among the paths after `--offset`, for log messages.
    index: usize,
    uri: String,
    kinds: Vec<ArtifactKind>,
}

/// The outcome of processing a single archive — passed back from each
/// concurrent task to the main task for merging.
///
/// We need this struct because each task runs independently and can't
/// mutate shared state. Instead, each task returns its results and the
/// main task merges them sequentially — no locks needed.
struct ArchiveResult {
    shard: Shard,
    /// What each extractor found, tagged with its Artifact kind.
    found: Vec<(ArtifactKind, Sightings)>,
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
            eprintln!("Usage: cc-extract <INPUT> [OPTIONS]");
            eprintln!("       cc-extract merge <INPUT_DIRS>...");
            process::exit(1);
        }
    };

    run_crawl(input, config).await;
}

/// Merge partial results from multiple SLURM task output directories.
///
/// Every Artifact kind is merged whose results file exists in at least one
/// of the directories, so `merge` needs no option to say which kinds the
/// tasks extracted.
fn run_merge(input_dirs: &[PathBuf], output_dir: &str) {
    eprintln!(
        "Merging results from {} directories into '{}'",
        input_dirs.len(),
        output_dir
    );

    let mut merged_any = false;
    for &kind in ArtifactKind::all() {
        let Some(merged) = merge_sightings_from(kind, input_dirs) else {
            continue;
        };
        merged_any = true;
        eprintln!("Merged: {}", count_list([(kind, merged.len())]));

        match save_sightings_to(kind, &merged, output_dir) {
            Ok(()) => {
                let path = Path::new(output_dir).join(kind.output_filename());
                eprintln!("{} results saved to {}", kind, path.display());
            }
            Err(err) => {
                eprintln!("Error saving merged {} results: {}", kind, err);
                process::exit(1);
            }
        }
    }

    if !merged_any {
        eprintln!("Error: no loadable results file in any of the input directories");
        process::exit(1);
    }
}

/// Unwrap loaded results, or stop the run before anything is saved.
///
/// Every finished archive saves the results files again, so carrying on
/// with an empty map would overwrite a file that merely failed to load.
fn load_or_exit(loaded: Result<Sightings, Box<dyn Error>>) -> Sightings {
    loaded.unwrap_or_else(|err| {
        eprintln!("Error: {}", err);
        eprintln!(
            "Stopping so the file is not overwritten. Files written before the \
             `page_url` / `shard` format are not converted: move the file away or \
             use another --output-dir."
        );
        process::exit(1);
    })
}

/// Save every requested kind's results file, reporting each one.
fn save_all(results: &BTreeMap<ArtifactKind, Sightings>, output_dir: &str) {
    for (&kind, sightings) in results {
        match save_sightings_to(kind, sightings, output_dir) {
            Ok(()) => {
                let path = Path::new(output_dir).join(kind.output_filename());
                eprintln!("{} results saved to {}", kind, path.display());
            }
            Err(err) => eprintln!("Error saving {} results: {}", kind, err),
        }
    }
}

/// Main crawl pipeline — download and parse WARC archives.
async fn run_crawl(input: String, config: Config) {
    let limit_display = match config.limit {
        Some(n) => format!("{}", n),
        None => "all".to_string()
    };

    // `-e onion,onion` would otherwise run two onion extractors.
    // `sort` + `dedup` drops repeats (`dedup` only removes *adjacent*
    // duplicates, hence the sort first); kinds then come in declaration order.
    let mut kinds = config.extract.clone();
    kinds.sort();
    kinds.dedup();

    let transport_choice = config.transport;
    let onion_engine = config.onion_engine;

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

    // --- Cap concurrent jobs based on available RAM (memory Transport only) ---
    //
    // ## Defensive resource management
    //
    // With `--transport memory`, each concurrent job holds an entire archive
    // in memory (~800 MB–1 GB). Without a cap, a 16-core machine with 8 GB
    // of RAM would try to hold 16 archives simultaneously — guaranteed OOM.
    //
    // We query available RAM once at startup and compute the maximum safe
    // number of concurrent in-memory jobs. `buffer_unordered` then provides
    // natural backpressure: when a job finishes and frees its buffer, the
    // next one starts and allocates a new buffer.
    let effective_jobs = if transport_choice == TransportChoice::Memory {
        const MAX_ARCHIVE_SIZE: u64 = 1_073_741_824; // 1 GB worst case
        if let Some(available) = get_available_memory() {
            let max_jobs = (available / MAX_ARCHIVE_SIZE).max(1) as usize;
            if max_jobs < capped_jobs {
                eprintln!(
                    "Warning: available RAM ({:.1} GB) limits in-memory jobs to {} \
                     (requested {}). Use --transport disk or free memory for more concurrency.",
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
        capped_jobs // Archives go to disk — no memory concern
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
        "Reading WARC paths from '{}' (extract: {}, limit: {}{}, jobs: {}, delete after: {}, \
         transport: {}, onion engine: {}{})",
        input, kind_list(&kinds), limit_display, offset_display, effective_jobs,
        config.delete, cli_name(&transport_choice), cli_name(&onion_engine), output_dir_display
    );

    // --- Open and read the paths file ---
    // Supports both plain text and gzip-compressed (.gz) paths files.
    // Common Crawl distributes warc.paths.gz — we decompress transparently
    // using `libflate`.
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
    //
    // Only the requested kinds' results are loaded, and only those files
    // are saved again: a run with `-e onion` never touches `favicons.json`.
    // A `BTreeMap` keeps the kinds in declaration order for the messages.
    let processed = load_processed_from(&config.output_dir);
    let mut results: BTreeMap<ArtifactKind, Sightings> = kinds
        .iter()
        .map(|&kind| (kind, load_or_exit(load_sightings_from(kind, &config.output_dir))))
        .collect();

    eprintln!(
        "State: {} (Shard, kind) pair(s) done; {} in results\n",
        processed.len(),
        count_list(results.iter().map(|(&kind, sightings)| (kind, sightings.len())))
    );

    // --- Schedule: the requested kinds still missing for each Shard ---
    //
    // We do this upfront so we know exactly which archives to process
    // concurrently. An Archive whose Shard is done for every requested kind
    // is skipped and doesn't count toward the limit; any other is scheduled
    // with only its missing kinds.
    let mut work_items: Vec<ScheduledArchive> = Vec::new();
    let mut skip_count: usize = 0;

    for (i, uri) in uris.iter().enumerate() {
        let filename = match filename_from_uri(uri) {
            Ok(f) => f,
            Err(err) => {
                eprintln!("[{}] {}: {}", i + 1, uri, err);
                continue;
            }
        };

        let shard = Shard::from_archive_name(filename);
        let missing: Vec<ArtifactKind> = kinds
            .iter()
            .copied()
            .filter(|&kind| !processed.contains(&(shard.clone(), kind)))
            .collect();

        if missing.is_empty() {
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

        work_items.push(ScheduledArchive { index: i + 1, uri: uri.clone(), kinds: missing });
    }

    let output_dir = config.output_dir;

    if work_items.is_empty() {
        eprintln!("No archives to process.");
        save_all(&results, &output_dir);
        eprintln!(
            "\nSummary: 0 processed, {} skipped, 0 failed",
            skip_count
        );
        eprintln!(
            "Total in results: {}",
            count_list(results.iter().map(|(&kind, sightings)| (kind, sightings.len())))
        );
        return;
    }

    eprintln!("Processing {} archive(s) with {} concurrent job(s)\n", work_items.len(), effective_jobs);

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
    // `stream::iter(work_items)` creates a stream of scheduled archives.
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
        .map(|ScheduledArchive { index: idx, uri, kinds }| {
            // Clone the shared client for this task. `reqwest::Client` is
            // an `Arc` inside, so the clone is cheap (just increments a
            // reference count) and shares the connection pool.
            let client = client.clone();

            async move {
                let filename = match filename_from_uri(&uri) {
                    Ok(f) => f.to_string(),
                    Err(err) => {
                        eprintln!("[{}] {}: {}", idx, uri, err);
                        return Err(format!("{}: {}", uri, err));
                    }
                };

                eprintln!("[{}] {}: extracting {}", idx, filename, kind_list(&kinds));

                // --- Download phase ---
                //
                // With the memory Transport, we download to memory
                // (`Vec<u8>`) instead of disk. The compressed bytes stay in
                // RAM and are passed directly to the parser. The other two
                // write to `download/<filename>` first, unless the file is
                // already there. Either way the result is the `Transport`
                // the parser reads from.
                let local_path: PathBuf = Path::new("download").join(&filename);
                let download_start = Instant::now();

                let transport = match transport_choice {
                    TransportChoice::Memory => {
                        match download_warc_to_memory(&client, &uri).await {
                            Ok(data) => Transport::Memory(data),
                            Err(err) => {
                                eprintln!("  [{}] Download error: {}", filename, err);
                                return Err(format!("{}: download error: {}", filename, err));
                            }
                        }
                    }
                    TransportChoice::Disk | TransportChoice::Mmap => {
                        if !local_path.exists() {
                            if let Err(err) = download_warc_async(&client, &uri).await {
                                eprintln!("  [{}] Download error: {}", filename, err);
                                return Err(format!("{}: download error: {}", filename, err));
                            }
                        } else {
                            eprintln!("  [{}] Already downloaded", filename);
                        }
                        if transport_choice == TransportChoice::Mmap {
                            Transport::Mmap(local_path.clone())
                        } else {
                            Transport::Disk(local_path.clone())
                        }
                    }
                };

                let download_time = download_start.elapsed();
                eprintln!("  [{}] Download time: {:.1}s", filename, download_time.as_secs_f64());

                // --- Parse on the blocking thread pool ---
                //
                // ## `spawn_blocking` — bridging sync and async
                //
                // `parse_archive` is CPU-bound (gzip decompression + search).
                // Running it directly on an async task would block the Tokio
                // worker thread, starving other async tasks (downloads).
                //
                // `spawn_blocking` moves the work to Tokio's dedicated
                // blocking thread pool, which has many more threads and
                // expects blocking work. The `.await` here suspends the
                // async task until the blocking work finishes, freeing the
                // worker thread for other downloads.
                //
                // With the memory Transport, the `Vec<u8>` inside
                // `Transport::Memory` is *moved* into the blocking closure —
                // a zero-cost ownership transfer (no data copying). After the
                // move, the async task no longer owns the buffer, and the
                // compiler prevents use-after-move.
                eprintln!("  [{}] Parsing ({})...", filename, cli_name(&transport_choice));
                let shard = Shard::from_archive_name(&filename);
                // The closure takes ownership of what it captures; the clone
                // keeps a `shard` here for the result.
                let parse_shard = shard.clone();

                let parse_start = Instant::now();
                let parse_result = tokio::task::spawn_blocking(
                    move || -> Result<Vec<(ArtifactKind, Sightings)>, Box<dyn Error + Send + Sync>> {
                        // One boxed extractor per kind still missing for this Shard.
                        let mut extractors: Vec<Box<dyn Extractor>> = kinds
                            .iter()
                            .map(|&kind| new_extractor(kind, onion_engine))
                            .collect();
                        parse_archive(transport, &parse_shard, &mut extractors)?;
                        Ok(extractors
                            .into_iter()
                            .map(|extractor| (extractor.kind(), extractor.into_sightings()))
                            .collect())
                    },
                )
                .await;
                let parse_time = parse_start.elapsed();

                // `spawn_blocking` returns a `JoinHandle` — unwrap the
                // outer Result (task panic) then the inner Result (parse error).
                let found = match parse_result {
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
                    "  [{}] Found {}",
                    filename,
                    count_list(found.iter().map(|(kind, sightings)| (*kind, sightings.len())))
                );

                Ok((filename, local_path, ArchiveResult {
                    shard,
                    found,
                    download_time,
                    parse_time
                }))
            }
        })
        .buffer_unordered(effective_jobs);

    // --- Collect results back on the main task ---
    //
    // `buffer_unordered` yields results as futures complete. We process
    // them sequentially here: merge Sightings into each kind's map, save
    // it, mark the (Shard, kind) pairs as done, and optionally delete files.
    //
    // This is a key design choice: concurrent *work*, sequential *merging*.
    // No locks, no race conditions — the simplest correct approach.
    let mut process_count: usize = 0;
    let mut fail_count: usize = 0;
    let mut new_counts: BTreeMap<ArtifactKind, usize> =
        kinds.iter().map(|&kind| (kind, 0)).collect();
    let mut total_download = Duration::ZERO;
    let mut total_parse = Duration::ZERO;

    // `pin_mut!` pins the stream to the stack so we can poll it.
    // This is needed because `buffer_unordered` returns a stream that
    // must be pinned to be polled (a Rust async trait requirement).
    futures::pin_mut!(archive_stream);

    while let Some(task_result) = archive_stream.next().await {
        match task_result {
            Ok((filename, local_path, archive)) => {
                total_download += archive.download_time;
                total_parse += archive.parse_time;

                // For each kind: merge, save its file, *then* mark the pair
                // done. A crash or failed write in between leaves the pair
                // unmarked, never marked with its Sightings unsaved (see
                // `save_then_mark`).
                for (kind, sightings) in archive.found {
                    // Extractors only run for requested kinds, and every
                    // requested kind was loaded. Inserting an empty map here
                    // instead would overwrite a results file never loaded.
                    let all = results
                        .get_mut(&kind)
                        .expect("results are loaded for every requested kind");
                    let count_before = all.len();
                    merge_sightings(all, sightings);
                    *new_counts.entry(kind).or_default() += all.len() - count_before;

                    if let Err(err) = save_then_mark(kind, all, &archive.shard, &output_dir) {
                        eprintln!(
                            "  [{}] Warning: {} will be extracted again next run: {}",
                            filename, kind, err
                        );
                    }
                }

                process_count += 1;

                // With the memory Transport there is no local file to
                // delete — the data was parsed from memory and already dropped.
                if delete && transport_choice != TransportChoice::Memory {
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
    save_all(&results, &output_dir);

    // --- Summary ---
    eprintln!(
        "\nSummary: {} processed, {} skipped, {} failed, new: {}",
        process_count,
        skip_count,
        fail_count,
        count_list(new_counts)
    );
    eprintln!(
        "Total in results: {}",
        count_list(results.iter().map(|(&kind, sightings)| (kind, sightings.len())))
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
