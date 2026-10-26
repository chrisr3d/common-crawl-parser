// cc-extract library — download, parsing, and state management
//
// This module ties the pieces together:
//   - Downloading Archives from Common Crawl (async with reqwest)
//   - `parse_archive`: reading every record of an Archive once and handing
//     it to each extractor
//   - Persistent state: processed log and results JSON
//
// ## Three independent choices
//
// Parsing an Archive combines three things that vary independently:
//   - Transport: how the compressed bytes arrive (a file on disk, a buffer
//     in memory, or a decompressed copy that is memory-mapped), see
//     `Transport` below
//   - Format: how records are read; WARC only for now (`warc_parser`,
//     `page_record`)
//   - Artifact kind: what is extracted, one `Extractor` per kind
//     (`extractor`, `artifact`)
//
// `parse_archive` only connects them: a new kind needs its own `Extractor`
// (and its output file), but the parsing loop stays as it is.
//
// Which Formats are read for a Shard is the planner's choice (`plan`): the
// cheapest Archives that serve every requested kind (`format` says what
// Common Crawl publishes and where).

pub mod artifact;
pub mod extractor;
pub mod favicon_search;
pub mod format;
pub mod onion_search;
pub mod page_record;
pub mod plan;
pub mod warc_parser;

// Re-exports: the types callers need most, importable from the crate root
// (`cc_extract::Sighting` rather than `cc_extract::artifact::Sighting`).
pub use artifact::{ArtifactKind, Shard, Sighting, Sightings, merge_sightings};
pub use extractor::{Extractor, FaviconExtractor, OnionEngine, OnionExtractor};
pub use format::{ArchivePath, Dataset, Format, FormatSet};
pub use plan::{FormatRequirement, Plan, PlanError};
pub use page_record::{PageRecord, WarcResponse};

use std::collections::HashSet;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, BufReader, Cursor, Read, Write};
use std::path::{Path, PathBuf};

use flate2::read::MultiGzDecoder;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Base URL for Common Crawl data archives.
const COMMONCRAWL_BASE: &str = "https://data.commoncrawl.org/";

/// Default directory for output files.
pub const DEFAULT_OUTPUT_DIR: &str = "output";

/// Filename for the log of done (Shard, Artifact kind) pairs. Each kind's
/// results file is named by `ArtifactKind::output_filename`.
pub const PROCESSED_FILENAME: &str = "processed.log";

// ---------------------------------------------------------------------------
// Download Logic
// ---------------------------------------------------------------------------

/// Download one Archive from Common Crawl to `download/` using async I/O.
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
pub async fn download_archive(
    client: &reqwest::Client,
    archive: &ArchivePath,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let url = format!("{}{}", COMMONCRAWL_BASE, archive.uri());
    let filename = archive.file_name();
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

/// Download one Archive into memory instead of to disk.
///
/// ## Why in-memory?
///
/// The disk-based pipeline writes every byte to disk during download, then
/// reads it back for parsing — the data crosses the I/O boundary twice.
/// By collecting chunks into a `Vec<u8>`, we skip disk I/O entirely and
/// parse directly from memory.
///
/// ## `Vec::with_capacity` — pre-allocation
///
/// When `Content-Length` is available, we pre-allocate the buffer to the
/// exact size. Without this, `Vec` grows geometrically (double on each
/// reallocation), which means ~30 allocate-copy-free cycles for an 800 MB
/// download. Pre-allocation does it in one shot.
///
/// ## Trade-off: memory vs disk
///
/// A WARC Archive is ~1 GB compressed. With `-j 4`, that's ~4 GB of RAM.
/// This is acceptable for modern machines and comparable to what the `mmap`
/// Transport uses in virtual memory. The benefit is zero disk usage in the
/// `download/` directory.
pub async fn download_archive_to_memory(
    client: &reqwest::Client,
    archive: &ArchivePath,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let url = format!("{}{}", COMMONCRAWL_BASE, archive.uri());
    let filename = archive.file_name();

    eprintln!("  [{}] Downloading to memory...", filename);
    eprintln!("  [{}] URL: {}", filename, url);

    let mut response = client.get(&url).send().await?.error_for_status()?;

    let total_size = response.content_length();
    if let Some(size) = total_size {
        eprintln!("  [{}] Size: {:.1} MB", filename, size as f64 / 1_048_576.0);
    }

    // Pre-allocate the buffer when the size is known, avoiding repeated
    // geometric-growth reallocations (each doubling copies all existing data).
    let mut buffer: Vec<u8> = Vec::with_capacity(total_size.unwrap_or(0) as usize);
    let mut bytes_read: u64 = 0;
    let mut last_report: u64 = 0;

    while let Some(chunk) = response.chunk().await? {
        buffer.extend_from_slice(&chunk);
        bytes_read += chunk.len() as u64;

        if bytes_read - last_report >= 10 * 1_048_576 {
            last_report = bytes_read;
            match total_size {
                Some(total) => {
                    let pct = (bytes_read as f64 / total as f64) * 100.0;
                    eprint!(
                        "\r  [{}] Progress: {:.1} MB / {:.1} MB ({:.0}%)",
                        filename,
                        bytes_read as f64 / 1_048_576.0,
                        total as f64 / 1_048_576.0,
                        pct
                    );
                }
                None => {
                    eprint!(
                        "\r  [{}] Progress: {:.1} MB",
                        filename,
                        bytes_read as f64 / 1_048_576.0
                    );
                }
            }
        }
    }

    if last_report > 0 {
        eprintln!();
    }

    eprintln!(
        "  [{}] Done: {:.1} MB in memory",
        filename,
        bytes_read as f64 / 1_048_576.0
    );

    Ok(buffer)
}

// ---------------------------------------------------------------------------
// Parsing an Archive
// ---------------------------------------------------------------------------

/// How the compressed bytes of an Archive reach the parser.
///
/// ## Enums with data
///
/// Each variant carries what that way of reading needs: a path for the two
/// file-based Transports, the downloaded bytes themselves for `Memory`. A
/// `Memory` value without bytes, or a `Disk` value without a path, can't be
/// built, so `parse_archive` never has to handle one.
pub enum Transport {
    /// Stream-decompress a `.warc.gz` file on disk.
    Disk(PathBuf),
    /// Stream-decompress a `.warc.gz` already downloaded into memory.
    Memory(Vec<u8>),
    /// Decompress a `.warc.gz` file to a temporary `.warc` next to it, then
    /// memory-map that copy and read records straight from the mapping.
    Mmap(PathBuf),
}

/// Progress is reported every this many records.
const PROGRESS_EVERY: u64 = 10_000;

/// Read every record of one Archive once and hand it to every extractor.
///
/// When this returns, each extractor holds what it found in the Archive;
/// `Extractor::into_sightings` hands that over. The function itself never
/// looks at which Artifact kinds it is feeding.
///
/// ## Synchronous on purpose
///
/// Parsing is CPU-bound (gzip decompression + searching), not I/O-bound.
/// Async shines for I/O waits (network, slow disk); for CPU work it just
/// adds overhead. The pipeline in `main` calls this from `spawn_blocking`,
/// which runs it on Tokio's dedicated blocking thread pool: the idiomatic
/// way to mix sync CPU work with async I/O in Tokio.
///
/// ## `Transport::Memory`: ownership transfer
///
/// The `Vec<u8>` inside `Transport::Memory` is *moved* in. When called from
/// `spawn_blocking(move || ...)`, the ~800 MB buffer changes owner without
/// being copied, and the compiler prevents the async task from using it
/// afterwards.
pub fn parse_archive(
    transport: Transport,
    shard: &Shard,
    extractors: &mut [Box<dyn Extractor>],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let records_scanned = match transport {
        // `File` and `Cursor<Vec<u8>>` both implement `Read`, so one
        // streaming loop serves both.
        Transport::Disk(path) => parse_stream(fs::File::open(path)?, shard, extractors)?,
        Transport::Memory(data) => parse_stream(Cursor::new(data), shard, extractors)?,
        Transport::Mmap(path) => parse_mmap(&path, shard, extractors)?,
    };

    if records_scanned >= PROGRESS_EVERY {
        eprintln!(); // End the `\r` progress line.
    }
    Ok(())
}

/// Parse a gzipped WARC stream with the streaming record parser.
///
/// ## `std::io::Cursor` — the adapter pattern
///
/// `Cursor<Vec<u8>>` wraps a byte vector and implements the `Read` trait,
/// making it interchangeable with a `File`. `MultiGzDecoder` doesn't care
/// whether its inner `Read` is a file on disk or bytes in memory — it just
/// calls `.read()`. Same interface, different backing store.
///
/// `MultiGzDecoder` (not `GzDecoder`) because Common Crawl gzips every
/// record as its own gzip member; `GzDecoder` would stop after the first.
fn parse_stream<R: Read>(
    compressed: R,
    shard: &Shard,
    extractors: &mut [Box<dyn Extractor>],
) -> io::Result<u64> {
    let decoder = MultiGzDecoder::new(compressed);
    let records = warc_parser::WarcRecordIter::new(BufReader::new(decoder));
    let mut records_scanned = 0;

    for record in records {
        let record = record?;
        // The `PageRecord` borrows the record's own buffers: nothing is
        // copied, and it is dropped before the next record is read.
        let page = PageRecord::Warc(WarcResponse {
            page_url: &record.target_uri,
            date: &record.date,
            http_response: &record.body,
        });
        hand_over(&page, shard, extractors, &mut records_scanned);
    }

    Ok(records_scanned)
}

/// Parse a WARC Archive through memory-mapped I/O.
///
/// ## How mmap works here
///
/// WARC archives are gzip-compressed, and gzip is a streaming format —
/// you can't random-access into compressed data. So we decompress the
/// entire archive to a temporary file first, then memory-map that file.
///
/// Memory mapping means the OS maps the file's contents directly into
/// our virtual address space. Benefits:
/// - **Zero-copy**: record bodies are `&[u8]` slices into the mapped region,
///   no `Vec<u8>` allocation needed
/// - **OS page cache**: the kernel manages which pages are in RAM, doing a
///   better job than manual buffering for sequential access patterns
/// - **No read syscalls**: data access happens through page faults, handled
///   by the kernel's virtual memory system
///
/// The trade-off is disk space: a 1GB compressed archive decompresses to
/// ~3-5GB on disk.
fn parse_mmap(
    path: &Path,
    shard: &Shard,
    extractors: &mut [Box<dyn Extractor>],
) -> Result<u64, Box<dyn Error + Send + Sync>> {
    let filename = path.file_name().unwrap_or_default().to_string_lossy();

    let tmp_path = path.with_extension("warc");
    eprintln!("  [{}] Decompressing to temp file for mmap...", filename);
    {
        let file = fs::File::open(path)?;
        let mut decoder = MultiGzDecoder::new(file);
        let mut tmp_file = fs::File::create(&tmp_path)?;
        io::copy(&mut decoder, &mut tmp_file)?;
    }
    let tmp_size = fs::metadata(&tmp_path)?.len();
    eprintln!(
        "  [{}] Decompressed: {:.1} MB",
        filename,
        tmp_size as f64 / 1_048_576.0
    );

    let tmp_file = fs::File::open(&tmp_path)?;
    let mmap = unsafe { memmap2::Mmap::map(&tmp_file)? };
    let mut records_scanned = 0;

    for record in warc_parser::WarcSliceIter::new(&mmap) {
        // The slice parser returns raw header bytes; extractors want `&str`.
        // `from_utf8_lossy` returns a `Cow`: it borrows when the bytes are
        // valid UTF-8 (the usual case) and allocates only to replace
        // invalid ones.
        let page_url = String::from_utf8_lossy(record.target_uri);
        let date = String::from_utf8_lossy(record.date);
        let page = PageRecord::Warc(WarcResponse {
            page_url: &page_url,
            date: &date,
            http_response: record.body,
        });
        hand_over(&page, shard, extractors, &mut records_scanned);
    }

    drop(mmap);
    drop(tmp_file);
    if let Err(e) = fs::remove_file(&tmp_path) {
        eprintln!("  [{}] Warning: could not remove temp file: {}", filename, e);
    }

    Ok(records_scanned)
}

/// Hand one record to every extractor and report progress now and then.
///
/// The loop sees extractors only through the `Extractor` trait, so it works
/// unchanged for any set of Artifact kinds.
fn hand_over(
    record: &PageRecord<'_>,
    shard: &Shard,
    extractors: &mut [Box<dyn Extractor>],
    records_scanned: &mut u64,
) {
    for extractor in extractors.iter_mut() {
        extractor.extract(record, shard);
    }

    *records_scanned += 1;
    if records_scanned.is_multiple_of(PROGRESS_EVERY) {
        let found: Vec<String> = extractors
            .iter()
            .map(|e| format!("{} {}(s)", e.artifact_count(), e.kind()))
            .collect();
        eprint!(
            "\r  [{}] Scanning: {} records, {}",
            shard,
            records_scanned,
            found.join(", ")
        );
    }
}

// ---------------------------------------------------------------------------
// State Management
// ---------------------------------------------------------------------------

/// Load the (Shard, Artifact kind) pairs already done in `output_dir`.
///
/// `processed.log` holds one `<shard> <kind>` line per done pair (ADR-0002),
/// such as `CC-MAIN-20260305070756-20260305100756-00000 onion`. Lines
/// without a kind name this version knows are ignored: a bare Archive
/// name, as written before kinds were tracked, doesn't say which kinds were
/// extracted, so the Shard is simply processed again.
///
/// ## `HashSet` of tuples
///
/// `HashSet` stores unique values with O(1) average-case lookup via hashing.
/// A tuple is hashable when each of its fields is, so `(Shard, ArtifactKind)`
/// works as a key with no extra code, and "is `onion` done for this Shard?"
/// is one `contains(&(shard, kind))`.
///
/// ## HPC / batch mode
///
/// When running as a SLURM array job, each task uses its own output directory
/// (`--output-dir output/42/`) so concurrent jobs never contend on the same
/// files.
pub fn load_processed_from(output_dir: &str) -> HashSet<(Shard, ArtifactKind)> {
    let path = Path::new(output_dir).join(PROCESSED_FILENAME);
    let content = fs::read_to_string(path).unwrap_or_default();
    content
        .lines()
        // `filter_map` drops the lines for which the closure returns `None`;
        // `?` inside it returns that `None` early.
        .filter_map(|line| {
            let (shard, kind) = line.trim().split_once(' ')?;
            let kind = kind.parse::<ArtifactKind>().ok()?;
            // A Shard id has no Format suffix, so it is kept whole.
            Some((Shard::from_archive_name(shard), kind))
        })
        .collect()
}

/// Append one `<shard> <kind>` line to the processed log.
fn mark_processed_in(shard: &Shard, kind: ArtifactKind, output_dir: &str) -> io::Result<()> {
    fs::create_dir_all(output_dir)?;
    let path = Path::new(output_dir).join(PROCESSED_FILENAME);
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)?;
    writeln!(file, "{} {}", shard, kind)
}

/// Save `kind`'s Sightings, then record `shard` as done for `kind`.
///
/// ## Ordering for crash safety
///
/// The two writes can't happen at once, so the order decides what a crash
/// (or a failed write) between them leaves behind:
///
/// - save, then mark (this order): the Sightings are saved but the pair is
///   not marked. The next run processes the Shard again for this kind, and
///   the Sightings it finds are already in the file; `merge_sightings`
///   skips them, so the redo costs time but changes nothing.
/// - mark, then save: the pair is marked but its Sightings are lost, and
///   no later run would ever look for them again.
///
/// `?` returns as soon as the save fails, so the mark is never written
/// after a failed save.
pub fn save_then_mark(
    kind: ArtifactKind,
    sightings: &Sightings,
    shard: &Shard,
    output_dir: &str,
) -> Result<(), Box<dyn Error>> {
    save_sightings_to(kind, sightings, output_dir)?;
    mark_processed_in(shard, kind, output_dir)
        .map_err(|err| format!("saved, but could not mark {} {}: {}", shard, kind, err))?;
    Ok(())
}

/// Load `kind`'s saved Sightings from `output_dir`.
pub fn load_sightings_from(
    kind: ArtifactKind,
    output_dir: &str,
) -> Result<Sightings, Box<dyn Error>> {
    load_sightings(&Path::new(output_dir).join(kind.output_filename()))
}

/// Load one kind's saved Sightings; a missing file means none yet.
///
/// ## Why an unreadable file is an error, not an empty map
///
/// The crawl merges new Sightings into what this returns and saves the
/// result over the same file. Returning an empty map for a file it can't
/// read (corrupt, or written in an older format such as `url` / `archive`
/// instead of `page_url` / `shard`) would make that save silently replace
/// the file's contents. Failing here stops the run before anything is
/// written.
fn load_sightings(path: &Path) -> Result<Sightings, Box<dyn Error>> {
    if !path.exists() {
        return Ok(Sightings::new());
    }
    // `map_err` adds the path to the message: serde's error alone says
    // "missing field `page_url` at line 4" without naming the file.
    let content = fs::read_to_string(path)
        .map_err(|err| format!("cannot read {}: {}", path.display(), err))?;
    let sightings = serde_json::from_str(&content)
        .map_err(|err| format!("cannot load {}: {}", path.display(), err))?;
    Ok(sightings)
}

/// Save `kind`'s Sightings to its file in `output_dir`.
pub fn save_sightings_to(
    kind: ArtifactKind,
    sightings: &Sightings,
    output_dir: &str,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(output_dir)?;
    let path = Path::new(output_dir).join(kind.output_filename());
    let json = serde_json::to_string_pretty(sightings)?;
    fs::write(&path, json).map_err(|err| format!("cannot write {}: {}", path.display(), err))?;
    Ok(())
}

/// Merge `kind`'s Sightings saved in several output directories into one
/// deduplicated map; `None` when no directory has a loadable file for
/// `kind`.
///
/// ## HPC merge step
///
/// After a SLURM array job completes, each task has saved its results in a
/// separate output directory. The `merge` subcommand calls this once per
/// Artifact kind, deduplicating on `(page_url, shard)` pairs with the same
/// `merge_sightings` the crawl uses after each Archive. A file that can't
/// be loaded is reported and skipped, so one bad task doesn't block the
/// merge of all the others.
pub fn merge_sightings_from(kind: ArtifactKind, input_dirs: &[PathBuf]) -> Option<Sightings> {
    let mut merged: Option<Sightings> = None;

    for dir in input_dirs {
        let path = dir.join(kind.output_filename());
        if !path.exists() {
            continue;
        }
        match load_sightings(&path) {
            // `get_or_insert_with` creates the map the first time a file
            // is found, which is what turns `None` into `Some`.
            Ok(partial) => merge_sightings(merged.get_or_insert_with(Sightings::new), partial),
            Err(err) => eprintln!("Warning: {}, skipping it", err),
        }
    }

    merged
}
