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
use std::env::{self, VarError};
use std::error::Error;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::process::{self, ExitCode};
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use futures::stream::{self, StreamExt};

use cc_extract::store::{
    DEFAULT_SOCKET, PASSWORD_VARIABLE, Store, StoreResult, artifact_count, load_processed,
    save_then_mark,
};
use cc_extract::{
    ArchivePath, ArtifactKind, Extractor, FaviconExtractor, Findings, Format, FormatSet,
    HttpClient, InlineFaviconExtractor, KvrocksStore, OnionEngine, OnionExtractor, Plan,
    READ_TIMEOUT, Shard, StoreAddress, Transport, download_archive, download_archive_to_memory,
    download_path, parse_archive,
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
    /// Download into RAM, stream-decompress from there (no disk I/O; a job holds its Shard's Archives)
    Memory,
    /// Download to download/, decompress to a temporary file, memory-map it
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
        ArtifactKind::InlineFavicon => Box::new(InlineFaviconExtractor::new()),
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
        let output = Command::new("sysctl").args(["-n", key]).output().ok()?;
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
// `after_long_help` is printed at the end of `--help` only, so `-h` stays
// short. 2 is `clap`'s own exit status for invalid arguments.
#[derive(Parser)]
#[command(name = "cc-extract")]
#[command(
    about = "Extract artifacts, such as .onion addresses and favicon URLs, from Common Crawl archives"
)]
#[command(after_long_help = "\
Exit status:
  0  Every Shard taken on done for every requested kind (paths file lines it can't use are skipped)
  1  Stopped early, such as on a missing or unreadable paths file or an unreachable store: fix the cause, then run again
  2  Invalid option or value
  3  Some Shards left with kinds undone (failed download, parse or store write): run the same command again")]
struct Config {
    /// Path to a WARC, WAT or WET paths file (supports .gz)
    ///
    /// Any of the three locates every Format of each Shard, so the paths
    /// file doesn't decide which Formats are downloaded (see --formats).
    input: String,

    /// Maximum number of Shards to process (default: all)
    ///
    /// Shards already done for every requested kind are skipped and not
    /// counted, so a run repeated with the same --offset goes on past the
    /// paths the first run covered.
    #[arg(short, long)]
    limit: Option<usize>,

    /// Skip the first N paths in the file (for SLURM array partitioning)
    ///
    /// Combined with --limit, this gives each of several processes its own
    /// slice: process 0 gets --offset 0 --limit 1000, process 1 gets
    /// --offset 1000 --limit 1000, etc. (see examples/slurm/).
    #[arg(short, long, default_value_t = 0)]
    offset: usize,

    /// Number of concurrent download+parse tasks (default: number of CPU cores)
    //
    // The default is counted when the program starts, so `--help` would
    // show this machine's count: on a cluster, the login node's rather than
    // the compute node's. `hide_default_value` leaves it to the text above.
    #[arg(short, long, default_value_t = default_jobs(), hide_default_value = true)]
    jobs: usize,

    /// Delete each Shard's Archives once parsed
    #[arg(short, long)]
    delete: bool,

    /// Artifact kinds to extract, comma-separated
    ///
    /// A Shard is processed again only for the kinds not yet marked done
    /// for it in the store, so a kind can be added in a later run.
    //
    // ## Comma-delimited lists
    //
    // `Vec<ArtifactKind>` makes the option take several values;
    // `value_delimiter = ','` splits `-e onion,favicon` into two, each
    // parsed through `ArtifactKind`'s `ValueEnum` derive. The default is
    // written as the user would type it and split the same way, so
    // `--help` shows `[default: onion,favicon]`.
    #[arg(
        short,
        long,
        value_enum,
        value_delimiter = ',',
        default_value = "onion,favicon"
    )]
    extract: Vec<ArtifactKind>,

    /// Formats to download for every Shard, comma-separated (default: the
    /// cheapest ones serving every kind)
    ///
    /// Rejected if they can't serve a requested kind, or if a Shard's
    /// Dataset doesn't publish one of them. Each kind still reads the
    /// cheapest Formats it accepts among these; one no kind reads is not
    /// downloaded.
    //
    // `Option<Vec<_>>`: `None` when the flag is absent, so "not given" is
    // told apart from any list of values.
    #[arg(long, value_enum, value_delimiter = ',')]
    formats: Option<Vec<Format>>,

    /// How downloaded Archives reach the parser
    #[arg(short, long, value_enum, default_value_t = TransportChoice::Disk)]
    transport: TransportChoice,

    /// Search used to find .onion addresses
    #[arg(long, value_enum, default_value_t = OnionEngine::Memchr)]
    onion_engine: OnionEngine,

    /// kvrocks store receiving results and done marks: a Unix socket path, or a redis://host:port URL
    ///
    /// If the store needs a password, it is read from the
    /// CC_EXTRACT_KVROCKS_PASSWORD environment variable, never from an
    /// option: options show in `ps` and in shell history.
    //
    // `StoreAddress` implements `FromStr`, so `clap` parses the value with
    // it, the default included: a URL it refuses is an invalid value (exit
    // status 2), reported before anything runs.
    #[arg(long, value_name = "SOCKET|URL", default_value = DEFAULT_SOCKET)]
    kvrocks: StoreAddress,
}

// ---------------------------------------------------------------------------
// Per-Shard task input and result
// ---------------------------------------------------------------------------

/// One Shard to process: the Plan for the requested kinds not yet done for
/// it, and where the Plan's Archives are. Only those kinds' extractors run.
struct ScheduledShard {
    /// 1-based position among the paths after `--offset`, for log messages.
    index: usize,
    shard: Shard,
    plan: Plan,
    /// One Archive per Format in the Plan.
    archives: Vec<ArchivePath>,
}

/// The outcome of processing a single Shard — passed back from each
/// concurrent task to the main task for merging.
///
/// We need this struct because each task runs independently and can't
/// mutate shared state. Instead, each task returns its results and the
/// main task merges them sequentially — no locks needed.
struct ShardResult {
    shard: Shard,
    /// What each kind found, for the kinds whose Archives all parsed.
    found: Vec<(ArtifactKind, Findings)>,
    /// The kinds left undone because one of their Archives failed.
    undone: Vec<ArtifactKind>,
    /// The Archives that were downloaded and parsed.
    parsed: Vec<ArchivePath>,
    download_time: Duration,
    parse_time: Duration,
}

/// Download one Archive, unless the file Transports find it already in
/// `download/`, and return the `Transport` the parser reads it from.
///
/// With the memory Transport, the Archive is downloaded to memory
/// (`Vec<u8>`) instead of disk: the compressed bytes stay in RAM and are
/// passed directly to the parser.
async fn fetch(
    client: &HttpClient,
    archive: &ArchivePath,
    transport_choice: TransportChoice,
) -> Result<Transport, Box<dyn Error + Send + Sync>> {
    match transport_choice {
        TransportChoice::Memory => Ok(Transport::Memory(
            download_archive_to_memory(client, archive).await?,
        )),
        TransportChoice::Disk | TransportChoice::Mmap => {
            let local_path = download_archive(client, archive).await?;
            Ok(if transport_choice == TransportChoice::Mmap {
                Transport::Mmap(local_path)
            } else {
                Transport::Disk(local_path)
            })
        }
    }
}

/// Parse each downloaded Archive of one Shard with the extractors of the
/// kinds that read its Format.
///
/// Returns what each kind found, merged over the Archives it reads, and the
/// Archives that parsed. Sightings from different Archives are unioned
/// (`Findings::merge`), never joined record by record. An Archive that
/// fails to parse contributes nothing: its extractors, and what they found
/// before the error, are dropped.
fn parse_archives(
    downloaded: Vec<(ArchivePath, Transport)>,
    shard: &Shard,
    plan: &Plan,
    onion_engine: OnionEngine,
    transport_choice: TransportChoice,
) -> (BTreeMap<ArtifactKind, Findings>, Vec<ArchivePath>) {
    let mut found: BTreeMap<ArtifactKind, Findings> = BTreeMap::new();
    let mut parsed = Vec::new();

    for (archive, transport) in downloaded {
        // One boxed extractor per kind reading this Archive's Format.
        let kinds = plan.kinds_reading(archive.format());
        let mut extractors: Vec<Box<dyn Extractor>> = kinds
            .iter()
            .map(|&kind| new_extractor(kind, onion_engine))
            .collect();
        eprintln!(
            "  [{}] Parsing ({}) for {}...",
            archive.file_name(),
            cli_name(&transport_choice),
            kind_list(&kinds)
        );

        match parse_archive(transport, archive.format(), shard, &mut extractors) {
            Ok(()) => {
                for extractor in extractors {
                    let kind = extractor.kind();
                    found
                        .entry(kind)
                        .or_insert_with(|| Findings::empty(kind))
                        .merge(extractor.into_findings());
                }
                parsed.push(archive);
            }
            Err(err) => eprintln!("  [{}] Parse error: {}", archive.file_name(), err),
        }
    }

    (found, parsed)
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
///
/// ## Returning an `ExitCode`
///
/// `main` may return any type implementing the `Termination` trait, which
/// turns it into the process's exit status: `()` gives 0, an `ExitCode`
/// gives its own value. Returning it, rather than calling `process::exit`,
/// lets `main` end normally, so every value still alive is dropped first:
/// `process::exit` ends the process on the spot and runs no destructors.
/// None of the early stops, still `process::exit(1)`, leaves a value whose
/// `Drop` has work to do: they all come before anything is downloaded or
/// written.
#[tokio::main]
async fn main() -> ExitCode {
    // --- Parse CLI arguments (synchronous — runs before the async work) ---
    // `Config::parse()` is generated by the `clap` derive macro. It reads
    // `std::env::args()`, validates types, and exits with a help message
    // if required arguments are missing or `--help` is passed: `--help`
    // never reaches the store.
    let config = Config::parse();
    run_crawl(config).await
}

/// The password to send the store: the value of `PASSWORD_VARIABLE`, if
/// set. A value that isn't UTF-8 stops the run: sent as it could be read,
/// it would be another password.
fn store_password() -> Option<String> {
    match env::var(PASSWORD_VARIABLE) {
        Ok(password) => Some(password),
        Err(VarError::NotPresent) => None,
        Err(VarError::NotUnicode(_)) => {
            eprintln!("Error: {} is not valid UTF-8", PASSWORD_VARIABLE);
            process::exit(1);
        }
    }
}

/// Stop the run on a store reached but not read at start-up.
///
/// The return type `!` (*never*) says the function doesn't return:
/// `process::exit` ends the process. A `!` fits wherever a value is
/// expected, so `unwrap_or_else(|err| stop_unreadable(..))` type-checks as
/// giving whatever the `Ok` would have held.
fn stop_unreadable(address: &StoreAddress, err: Box<dyn Error + Send + Sync>) -> ! {
    eprintln!("Error: cannot read the store at {}: {}", address, err);
    process::exit(1);
}

/// How many Artifacts of each of `kinds` the store holds.
async fn totals(
    store: &mut impl Store,
    kinds: &[ArtifactKind],
) -> StoreResult<Vec<(ArtifactKind, usize)>> {
    let mut totals = Vec::with_capacity(kinds.len());
    for &kind in kinds {
        totals.push((kind, artifact_count(store, kind).await?));
    }
    Ok(totals)
}

/// The `Total in results` line of the summary, read from the store.
async fn print_totals(store: &mut impl Store, kinds: &[ArtifactKind]) {
    match totals(store, kinds).await {
        Ok(totals) => eprintln!("Total in results: {}", count_list(totals)),
        Err(err) => eprintln!("Warning: cannot count the results in the store: {}", err),
    }
}

/// Exit status of a run that went to the end but left some (Shard, kind)
/// pairs undone: running the same command again retries them. A run that
/// did everything exits with 0, one that stops early with 1. 2 is taken:
/// `clap` exits with it on invalid arguments.
const EXIT_UNDONE: u8 = 3;

/// Main crawl pipeline — download and parse each Shard's Archives.
///
/// Returns `EXIT_UNDONE` if a Shard was left with a kind undone, by a
/// failed download, parse or store write.
async fn run_crawl(config: Config) -> ExitCode {
    let input = config.input.clone();
    let limit_display = match config.limit {
        Some(n) => format!("{}", n),
        None => "all".to_string(),
    };

    // `-e onion,onion` would otherwise run two onion extractors.
    // `sort` + `dedup` drops repeats (`dedup` only removes *adjacent*
    // duplicates, hence the sort first); kinds then come in declaration order.
    let mut kinds = config.extract.clone();
    kinds.sort();
    kinds.dedup();

    let transport_choice = config.transport;
    let onion_engine = config.onion_engine;

    // --- Check forced Formats against the requested kinds ---
    //
    // Done before reading anything: whether `--formats` can serve a kind
    // doesn't depend on the Shard. Whether each Shard's Dataset publishes
    // those Formats is checked when it is planned, still before any
    // download.
    //
    // `if let … && let …` (a *let chain*, edition 2024) matches both
    // patterns in one condition, instead of two nested `if let`s.
    let forced = config.formats.as_deref().map(FormatSet::of);
    if let Some(forced) = forced
        && let Err(err) = Plan::within(forced, &kinds)
    {
        eprintln!("Error: {}", err);
        process::exit(1);
    }

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

    let formats_display = match forced {
        Some(forced) => format!(", formats: {}", forced),
        None => String::new(),
    };
    let offset_display = if config.offset > 0 {
        format!(", offset: {}", config.offset)
    } else {
        String::new()
    };
    let store_display = if config.kvrocks != StoreAddress::Socket(DEFAULT_SOCKET.into()) {
        format!(", store: {}", config.kvrocks)
    } else {
        String::new()
    };
    eprintln!(
        "Reading paths from '{}' (extract: {}{}, limit: {}{}, jobs: {}, delete after: {}, \
         transport: {}, onion engine: {}{})",
        input,
        kind_list(&kinds),
        formats_display,
        limit_display,
        offset_display,
        capped_jobs,
        config.delete,
        cli_name(&transport_choice),
        cli_name(&onion_engine),
        store_display
    );

    // --- Open and read the paths file ---
    // Supports both plain text and gzip-compressed (.gz) paths files.
    // Common Crawl distributes `warc.paths.gz`, `wat.paths.gz` and
    // `wet.paths.gz` — we decompress transparently using `libflate`.
    let file = File::open(&input).unwrap_or_else(|err| {
        eprintln!("Error: cannot open '{}': {}", input, err);
        process::exit(1);
    });

    let reader: Box<dyn BufRead> = if input.ends_with(".gz") {
        let decoder = libflate::gzip::Decoder::new(file).unwrap_or_else(|err| {
            eprintln!("Error: failed to decompress '{}': {}", input, err);
            process::exit(1);
        });
        Box::new(BufReader::new(decoder))
    } else {
        Box::new(BufReader::new(file))
    };

    // `lines()` yields one `Result` per line, and a read error (such as a
    // `.gz` paths file cut short) must stop the run: `filter_map(Result::ok)`
    // would drop it and go on with the lines read so far, as if they were
    // the whole file. Collecting into `Result<Vec<_>, _>` stops at the first
    // `Err` and returns it instead.
    let lines: Vec<String> = reader
        .lines()
        .collect::<Result<_, _>>()
        .unwrap_or_else(|err| {
            eprintln!("Error: cannot read '{}': {}", input, err);
            process::exit(1);
        });

    let uris: Vec<String> = lines
        .into_iter()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .skip(config.offset)
        .collect();

    if uris.is_empty() {
        eprintln!(
            "No paths found in '{}' (after offset {})",
            input, config.offset
        );
        process::exit(1);
    }

    eprintln!(
        "Found {} path(s) in file{}",
        uris.len(),
        if config.offset > 0 {
            format!(" (after skipping {})", config.offset)
        } else {
            String::new()
        }
    );

    // --- Connect to the store, read the done pairs ---
    //
    // After the checks that need no store, before anything is downloaded:
    // a store that can't be reached stops the run here. Only the done
    // marks are read; the results stay in the store.
    let mut store = KvrocksStore::connect(&config.kvrocks, store_password())
        .await
        .unwrap_or_else(|err| {
            eprintln!(
                "Error: cannot reach the store at {}: {}",
                config.kvrocks, err
            );
            process::exit(1);
        });
    let processed = load_processed(&mut store)
        .await
        .unwrap_or_else(|err| stop_unreadable(&config.kvrocks, err));
    let start_totals = totals(&mut store, &kinds)
        .await
        .unwrap_or_else(|err| stop_unreadable(&config.kvrocks, err));

    eprintln!(
        "State: {} (Shard, kind) pair(s) done; {} in the store\n",
        processed.len(),
        count_list(start_totals)
    );

    // --- Schedule: the requested kinds still missing for each Shard ---
    //
    // We do this upfront so we know exactly which Shards to process
    // concurrently. A Shard done for every requested kind is skipped and
    // doesn't count toward the limit; any other is planned for its missing
    // kinds only, and its Plan's Archive paths are derived from the line.
    let mut work_items: Vec<ScheduledShard> = Vec::new();
    let mut skip_count: usize = 0;

    for (i, uri) in uris.iter().enumerate() {
        let path = match ArchivePath::parse(uri) {
            Ok(path) => path,
            Err(err) => {
                eprintln!("[{}] {}: {}", i + 1, uri, err);
                continue;
            }
        };

        let shard = path.shard();
        let missing: Vec<ArtifactKind> = kinds
            .iter()
            .copied()
            .filter(|&kind| !processed.contains(&(shard.clone(), kind)))
            .collect();

        if missing.is_empty() {
            eprintln!("[{}] {} — already processed, skipping", i + 1, shard);
            skip_count += 1;
            continue;
        }

        if let Some(limit) = config.limit
            && work_items.len() >= limit
        {
            eprintln!("Reached processing limit of {}. Stopping.", limit);
            break;
        }

        // A Plan fails only on a configuration no Shard of this Dataset can
        // meet (such as `--formats wat` on CC-NEWS), so the run stops here,
        // before anything is downloaded.
        let plan = Plan::new(path.dataset(), &missing, forced).unwrap_or_else(|err| {
            eprintln!("Error: [{}] {}: {}", i + 1, shard, err);
            process::exit(1);
        });

        // `collect` into `Option<Vec<_>>` gives `None` if any Format's path
        // can't be derived.
        let archives: Option<Vec<ArchivePath>> = plan
            .formats()
            .iter()
            .map(|format| path.in_format(format))
            .collect();
        let Some(archives) = archives else {
            eprintln!(
                "[{}] {}: cannot derive the paths of {} from it",
                i + 1,
                uri,
                plan.formats()
            );
            continue;
        };

        work_items.push(ScheduledShard {
            index: i + 1,
            shard,
            plan,
            archives,
        });
    }

    if work_items.is_empty() {
        eprintln!("No Shards to process.");
        eprintln!("\nSummary: 0 processed, {} skipped, 0 failed", skip_count);
        print_totals(&mut store, &kinds).await;
        return ExitCode::SUCCESS;
    }

    // --- Cap concurrent jobs based on available RAM (memory Transport only) ---
    //
    // ## Defensive resource management
    //
    // With `--transport memory`, each concurrent job holds every Archive of
    // its Shard's Plan in memory (~1 GB for WARC, less for WAT + WET).
    // Without a cap, a 16-core machine with 8 GB of RAM would try to hold
    // 16 Plans simultaneously — guaranteed OOM.
    //
    // We query available RAM once, after scheduling, and divide it by the
    // largest estimated Plan among the scheduled Shards: the worst case of
    // what one job can hold. `buffer_unordered` then provides natural
    // backpressure: when a job finishes and frees its buffers, the next one
    // starts and allocates new ones.
    let effective_jobs = if transport_choice == TransportChoice::Memory {
        let largest_plan = work_items
            .iter()
            .map(|item| item.plan.formats().estimated_size())
            .max()
            .unwrap_or(1)
            .max(1); // never divide by zero
        if let Some(available) = get_available_memory() {
            let max_jobs = (available / largest_plan).max(1) as usize;
            if max_jobs < capped_jobs {
                eprintln!(
                    "Warning: available RAM ({:.1} GB) limits in-memory jobs to {} \
                     (requested {}, up to {:.1} GB per Shard). Use --transport disk or \
                     free memory for more concurrency.",
                    available as f64 / 1_073_741_824.0,
                    max_jobs,
                    capped_jobs,
                    largest_plan as f64 / 1_073_741_824.0,
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

    eprintln!(
        "Processing {} Shard(s) with {} concurrent job(s)\n",
        work_items.len(),
        effective_jobs
    );

    // --- Create a shared HTTP client ---
    //
    // `reqwest::Client`, inside `HttpClient`, maintains a connection pool.
    // Sharing one client across all tasks lets them reuse TCP connections to
    // the same server (HTTP keep-alive), which is faster than each task
    // opening its own connection. A download receiving no data for
    // `READ_TIMEOUT` fails like any other download error.
    let client = HttpClient::new(READ_TIMEOUT).expect("Failed to build HTTP client");

    let delete = config.delete;

    // --- Concurrent pipeline with `buffer_unordered` ---
    //
    // ## How the pipeline works
    //
    // `stream::iter(work_items)` creates a stream of scheduled Shards.
    // `.map(|item| async { ... })` transforms each into a future that
    // downloads + parses one Shard's Archives.
    //
    // `.buffer_unordered(jobs)` is the concurrency controller:
    // - It polls up to `jobs` futures simultaneously
    // - Results are yielded as soon as any future completes (not in order)
    // - When one completes, the next pending future starts
    //
    // This gives us bounded concurrency without manual semaphore management.
    // "Unordered" means faster Shards finish first — we don't block
    // waiting for a slow download just because it started earlier.
    let shard_stream = stream::iter(work_items)
        .map(
            |ScheduledShard {
                 index: idx,
                 shard,
                 plan,
                 archives,
             }| {
                // Clone the shared client for this task. The `reqwest::Client`
                // in `HttpClient` is an `Arc` inside, so the clone is cheap
                // (just increments a reference count) and shares the
                // connection pool.
                let client = client.clone();

                async move {
                    let kinds = plan.kinds();
                    eprintln!(
                        "[{}] {}: extracting {} from {}",
                        idx,
                        shard,
                        kind_list(&kinds),
                        plan.formats()
                    );

                    // --- Download phase ---
                    //
                    // Every Archive of the Plan, one after the other (Shards
                    // already download concurrently). A failed download is
                    // reported and the Shard carries on: the kinds that don't
                    // read that Archive can still finish.
                    let download_start = Instant::now();
                    let mut downloaded: Vec<(ArchivePath, Transport)> = Vec::new();
                    for archive in archives {
                        match fetch(&client, &archive, transport_choice).await {
                            Ok(transport) => downloaded.push((archive, transport)),
                            Err(err) => {
                                eprintln!("  [{}] Download error: {}", archive.file_name(), err)
                            }
                        }
                    }
                    let download_time = download_start.elapsed();
                    eprintln!(
                        "  [{}] Download time: {:.1}s",
                        shard,
                        download_time.as_secs_f64()
                    );

                    if downloaded.is_empty() {
                        return ShardResult {
                            shard,
                            found: Vec::new(),
                            undone: kinds,
                            parsed: Vec::new(),
                            download_time,
                            parse_time: Duration::ZERO,
                        };
                    }

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
                    // With the memory Transport, the `Vec<u8>` inside each
                    // `Transport::Memory` is *moved* into the blocking closure —
                    // a zero-cost ownership transfer (no data copying). After the
                    // move, the async task no longer owns the buffers, and the
                    // compiler prevents use-after-move.
                    //
                    // The closure takes ownership of what it captures; the
                    // clones keep a `shard` and a `plan` here for the result.
                    let parse_shard = shard.clone();
                    let parse_plan = plan.clone();

                    let parse_start = Instant::now();
                    let parse_result = tokio::task::spawn_blocking(move || {
                        parse_archives(
                            downloaded,
                            &parse_shard,
                            &parse_plan,
                            onion_engine,
                            transport_choice,
                        )
                    })
                    .await;
                    let parse_time = parse_start.elapsed();

                    // `spawn_blocking` returns a `JoinHandle`, whose `Err` means
                    // the task panicked: then no Archive counts as parsed.
                    let (mut by_kind, parsed) = parse_result.unwrap_or_else(|err| {
                        eprintln!("  [{}] Task panic: {}", shard, err);
                        (BTreeMap::new(), Vec::new())
                    });
                    eprintln!(
                        "  [{}] Parsing time: {:.1}s",
                        shard,
                        parse_time.as_secs_f64()
                    );

                    // A kind is done only if every Archive it reads parsed; the
                    // others' partial Sightings are dropped.
                    let parsed_formats: FormatSet =
                        parsed.iter().map(ArchivePath::format).collect();
                    let (done, undone) = plan.split_done(parsed_formats);
                    let found: Vec<(ArtifactKind, Findings)> = done
                        .into_iter()
                        .map(|kind| {
                            let findings = by_kind.remove(&kind);
                            (kind, findings.unwrap_or_else(|| Findings::empty(kind)))
                        })
                        .collect();

                    if !found.is_empty() {
                        eprintln!(
                            "  [{}] Found {}",
                            shard,
                            count_list(
                                found.iter().map(|(kind, findings)| (*kind, findings.len()))
                            )
                        );
                    }

                    ShardResult {
                        shard,
                        found,
                        undone,
                        parsed,
                        download_time,
                        parse_time,
                    }
                }
            },
        )
        .buffer_unordered(effective_jobs);

    // --- Collect results back on the main task ---
    //
    // `buffer_unordered` yields results as futures complete. We process
    // them sequentially here: write each done kind's Sightings to the
    // store, mark the (Shard, kind) pair done, and optionally delete files.
    //
    // This is a key design choice: concurrent *work*, sequential *writing*.
    // No locks, no race conditions — the simplest correct approach.
    //
    // ## Writes pause the downloads
    //
    // The Shard futures are not spawned: `buffer_unordered` polls them, and
    // only when this loop asks for the next result. While a Shard is
    // written, the downloads in flight are not polled. A download left
    // unpolled for `READ_TIMEOUT` fails on its next poll, data or not, so a
    // write must stay well under it: one Shard's writes cost the same
    // however much the store already holds.
    let mut process_count: usize = 0;
    let mut fail_count: usize = 0;
    let mut new_counts: BTreeMap<ArtifactKind, usize> =
        kinds.iter().map(|&kind| (kind, 0)).collect();
    let mut total_download = Duration::ZERO;
    let mut total_parse = Duration::ZERO;

    // `pin_mut!` pins the stream to the stack so we can poll it.
    // This is needed because `buffer_unordered` returns a stream that
    // must be pinned to be polled (a Rust async trait requirement).
    futures::pin_mut!(shard_stream);

    while let Some(result) = shard_stream.next().await {
        // For each done kind: write its Sightings, *then* mark the pair
        // done. A crash or failed write in between leaves the pair
        // unmarked, never marked with its Sightings missing (see
        // `save_then_mark`). A kind whose write failed is left undone, like
        // one whose Archive failed.
        let mut undone = result.undone;
        let store_start = Instant::now();
        let wrote_any = !result.found.is_empty();
        for (kind, findings) in result.found {
            // Counted even when the write fails part-way: what it added
            // is in the store, and won't be new to the next run.
            let new_artifacts = new_counts.entry(kind).or_default();
            let saved = save_then_mark(&mut store, kind, &findings, &result.shard, new_artifacts);
            if let Err(err) = saved.await {
                eprintln!(
                    "  [{}] Error: cannot write {} to the store: {}",
                    result.shard, kind, err
                );
                undone.push(kind);
            }
        }
        if wrote_any {
            eprintln!(
                "  [{}] Store time: {:.1}s",
                result.shard,
                store_start.elapsed().as_secs_f64()
            );
        }

        if undone.is_empty() {
            process_count += 1;
            total_download += result.download_time;
            total_parse += result.parse_time;
        } else {
            // Kinds whose write failed were pushed last: back to declaration
            // order, as in every other kind list.
            undone.sort();
            eprintln!(
                "  [{}] Error: {} will be extracted again next run",
                result.shard,
                kind_list(&undone)
            );
            fail_count += 1;
        }

        // With the memory Transport there is no local file to delete — the
        // data was parsed from memory and already dropped. An Archive that
        // failed to parse is kept.
        if delete && transport_choice != TransportChoice::Memory {
            for archive in &result.parsed {
                let local_path = download_path(archive);
                match fs::remove_file(&local_path) {
                    Ok(()) => eprintln!("  [{}] Deleted {}", result.shard, local_path.display()),
                    Err(err) => eprintln!("  [{}] Warning: couldn't delete: {}", result.shard, err),
                }
            }
        }

        eprintln!();
    }

    // --- Summary ---
    eprintln!(
        "\nSummary: {} processed, {} skipped, {} failed, new: {}",
        process_count,
        skip_count,
        fail_count,
        count_list(new_counts)
    );
    print_totals(&mut store, &kinds).await;
    if process_count > 0 {
        let avg_dl = total_download.as_secs_f64() / process_count as f64;
        let avg_parse = total_parse.as_secs_f64() / process_count as f64;
        eprintln!(
            "Avg per Shard: {:.1}s download, {:.1}s parsing",
            avg_dl, avg_parse
        );
    }

    if fail_count > 0 {
        ExitCode::from(EXIT_UNDONE)
    } else {
        ExitCode::SUCCESS
    }
}
