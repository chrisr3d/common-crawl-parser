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
//   - Format: how records are read: WARC, WAT or WET (`warc_parser`,
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
pub mod inline_favicon;
pub mod onion_search;
pub mod page_record;
pub mod plan;
pub mod warc_parser;

// Re-exports: the types callers need most, importable from the crate root
// (`cc_extract::Sighting` rather than `cc_extract::artifact::Sighting`).
pub use artifact::{ArtifactKind, Findings, Shard, Sighting, Sightings, merge_sightings};
pub use extractor::{
    Extractor, FaviconExtractor, InlineFaviconExtractor, OnionEngine, OnionExtractor,
};
pub use format::{ArchivePath, Dataset, Format, FormatSet};
pub use inline_favicon::{InlineFavicon, InlineFavicons};
pub use page_record::{PageRecord, WarcResponse, WatMetadata, WetConversion};
pub use plan::{FormatRequirement, Plan, PlanError};

use std::collections::HashSet;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, BufReader, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::process;

use flate2::read::MultiGzDecoder;
use futures::stream::{self, Stream, TryStreamExt};
use tokio::io::AsyncWriteExt;

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
// Temporary files
// ---------------------------------------------------------------------------

/// `path` with `suffix` appended to its file name: `onions.json` and
/// `.tmp` give `onions.json.tmp`, in the same directory.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut file_name = path.file_name().unwrap_or_default().to_os_string();
    file_name.push(suffix);
    path.with_file_name(file_name)
}

/// A file removed when this value is dropped, unless `keep` was called.
///
/// ## Cleaning up on every way out with `Drop`
///
/// A function writing a temporary file can be left in many ways: each `?`
/// returns early with an error, and an async task can be dropped while it
/// waits at an `.await`. Rust runs `drop` on every local value whichever
/// way the function is left, so removing the file in `Drop` covers them all,
/// where a `remove_file` call before the final `Ok` would only cover the way
/// that reaches it.
///
/// A killed process runs no destructors. What it leaves is a file under a
/// temporary name, which no later run reads.
///
/// `drop` can't `.await`, so it removes the file with the blocking
/// `fs::remove_file`, in async code too: unlinking a file is one quick
/// system call, not worth handing to another thread.
struct TempFile {
    /// `None` once `keep` was called: there is nothing left to remove.
    path: Option<PathBuf>,
}

impl TempFile {
    fn new(path: PathBuf) -> Self {
        TempFile { path: Some(path) }
    }

    fn path(&self) -> &Path {
        self.path
            .as_deref()
            .expect("only `keep` takes the path, and it consumes the value")
    }

    /// Keep the file: called once it was renamed to its final name, so the
    /// drop at the end of `keep` has nothing to remove.
    fn keep(mut self) {
        self.path = None;
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let Some(path) = &self.path else { return };
        match fs::remove_file(path) {
            // An error may come before the file was created.
            Err(err) if err.kind() != io::ErrorKind::NotFound => {
                eprintln!("Warning: could not remove {}: {}", path.display(), err);
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Download Logic
// ---------------------------------------------------------------------------

/// Directory where the disk and mmap Transports keep downloaded Archives,
/// under the current directory.
const DOWNLOAD_DIR: &str = "download";

/// Where the disk and mmap Transports keep a downloaded Archive.
pub fn download_path(archive: &ArchivePath) -> PathBuf {
    Path::new(DOWNLOAD_DIR).join(archive.file_name())
}

/// Download one Archive from Common Crawl to `download/` using async I/O,
/// unless it is there already, and return its path there.
///
/// The one place that decides whether an Archive is downloaded: a file at
/// its name in `download/` is the Archive, complete, since `save_archive`
/// puts one there only once every byte arrived.
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
pub async fn download_archive(
    client: &reqwest::Client,
    archive: &ArchivePath,
) -> Result<PathBuf, Box<dyn Error + Send + Sync>> {
    let url = format!("{}{}", COMMONCRAWL_BASE, archive.uri());
    let filename = archive.file_name();
    let local_path = download_path(archive);

    if local_path.exists() {
        eprintln!("  [{}] Already downloaded, skipping download", filename);
        return Ok(local_path);
    }

    // `tokio::fs::create_dir_all` is the async version of `fs::create_dir_all`.
    // For file system operations, async doesn't help much (disk I/O is fast),
    // but it avoids blocking the Tokio runtime thread.
    tokio::fs::create_dir_all(DOWNLOAD_DIR).await?;

    eprintln!("  [{}] Downloading...", filename);
    eprintln!("  [{}] URL: {}", filename, url);

    let response = client.get(&url).send().await?.error_for_status()?;

    // Content-Length header tells us the total size (if the server provides it).
    let total_size = response.content_length();
    if let Some(size) = total_size {
        eprintln!("  [{}] Size: {:.1} MB", filename, size as f64 / 1_048_576.0);
    }

    // `response.chunk()` yields `Option<Bytes>`: each call returns the next
    // piece of the body, or `None` when complete. `try_unfold` turns those
    // calls into a `Stream`, the shape `save_archive` reads: it threads the
    // response from one call to the next, and stops at the first `None` or
    // error.
    let chunks = stream::try_unfold(response, |mut response| async move {
        let chunk = response.chunk().await?;
        Ok::<_, reqwest::Error>(chunk.map(|chunk| (chunk, response)))
    });
    save_archive(chunks, total_size, &local_path).await?;

    Ok(local_path)
}

/// Save an Archive's body, arriving as a stream of `chunks`, to
/// `local_path`.
///
/// ## Complete or absent
///
/// A file at `local_path` counts as the Archive, downloaded in full: the
/// next run parses it rather than downloading it again. So the chunks are
/// written to `<file name>.<process id>.part` next to it, and renamed to
/// `local_path` only once the stream ended and, when the server announced
/// a `Content-Length`, the byte count matches it. A failed download removes
/// its partial file (`TempFile`); a killed one leaves it, under a name no
/// run reads. The rename is atomic because both names are in the same
/// directory, hence on the same filesystem (see `save_sightings_to`).
///
/// `std::process::id()` makes the partial name unique per process on one
/// machine: several processes can share one `download/` and, on a re-run,
/// reach the same Shard. Each then writes its own partial file, never into
/// another's; the second rename replaces the first Archive with the same
/// bytes. (Process ids are unique per machine only: processes on several
/// nodes sharing one `download/` over a network filesystem could pick the
/// same one.)
///
/// ## Streaming download
///
/// Each chunk is written to disk as soon as it arrives, rather than
/// buffering the entire Archive (hundreds of MB) in memory. This keeps
/// memory usage constant regardless of Archive size. At each `.await`, the
/// task suspends and the thread can run other downloads.
///
/// ## Any stream of bytes
///
/// The function is generic over the `Stream` trait (from `futures`, the
/// async counterpart of `Iterator`): it reads chunks of any type that can be
/// viewed as bytes (`AsRef<[u8]>`), with any error type. The HTTP response
/// is one such stream; a test can build another from a `Vec`, without a
/// network.
pub async fn save_archive<S, B, E>(
    chunks: S,
    content_length: Option<u64>,
    local_path: &Path,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    S: Stream<Item = Result<B, E>>,
    B: AsRef<[u8]>,
    E: Error + Send + Sync + 'static,
{
    let filename = local_path.file_name().unwrap_or_default().to_string_lossy();
    // Reading a stream with `try_next` needs it pinned: a stream (such as
    // `try_unfold`'s) may hold a future that must not move in memory once
    // polled. `pin!` pins it on the stack.
    let mut chunks = pin!(chunks);
    let partial = TempFile::new(with_suffix(local_path, &format!(".{}.part", process::id())));
    let mut file = tokio::fs::File::create(partial.path()).await?;
    let mut bytes_written: u64 = 0;
    let mut last_report: u64 = 0;

    while let Some(chunk) = chunks.try_next().await? {
        let chunk = chunk.as_ref();
        file.write_all(chunk).await?;
        bytes_written += chunk.len() as u64;

        if bytes_written - last_report >= 10 * 1_048_576 {
            last_report = bytes_written;
            match content_length {
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

    // tokio's `File` hands each write to a background thread, and
    // `write_all` may return before the last one is done: `flush` waits for
    // it, so the file holds every byte before it gets its final name.
    file.flush().await?;
    drop(file);

    // The HTTP client already fails a body cut short of its
    // `Content-Length`; checking here as well keeps the rule in this
    // function, whatever stream it reads.
    if let Some(expected) = content_length
        && bytes_written != expected
    {
        return Err(format!(
            "received {} bytes, but Content-Length announced {}",
            bytes_written, expected
        )
        .into());
    }

    tokio::fs::rename(partial.path(), local_path).await?;
    partial.keep();

    eprintln!(
        "  [{}] Done: {:.1} MB written",
        filename,
        bytes_written as f64 / 1_048_576.0,
    );

    Ok(())
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
    /// Stream-decompress a gzipped Archive on disk.
    Disk(PathBuf),
    /// Stream-decompress a gzipped Archive already downloaded into memory.
    Memory(Vec<u8>),
    /// Decompress a gzipped Archive to a copy next to it, then memory-map
    /// that copy and read records straight from the mapping. On Unix the
    /// copy's name is removed as soon as it is created: no other process can
    /// open it, and its space is freed when the parse ends or the process
    /// dies. On Windows it keeps its name until the parse ends.
    Mmap(PathBuf),
}

/// Progress is reported every this many records.
const PROGRESS_EVERY: u64 = 10_000;

/// Read every page record of one `format` Archive once and hand it to
/// every extractor.
///
/// When this returns, each extractor holds what it found in the Archive;
/// `Extractor::into_findings` hands that over. The function itself never
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
    format: Format,
    shard: &Shard,
    extractors: &mut [Box<dyn Extractor>],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let records_scanned = match transport {
        // `File` and `Cursor<Vec<u8>>` both implement `Read`, so one
        // streaming loop serves both.
        Transport::Disk(path) => parse_stream(fs::File::open(path)?, format, shard, extractors)?,
        Transport::Memory(data) => parse_stream(Cursor::new(data), format, shard, extractors)?,
        Transport::Mmap(path) => parse_mmap(&path, format, shard, extractors)?,
    };

    if records_scanned >= PROGRESS_EVERY {
        eprintln!(); // End the `\r` progress line.
    }
    Ok(())
}

/// Parse a gzipped Archive with the streaming record parser.
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
    format: Format,
    shard: &Shard,
    extractors: &mut [Box<dyn Extractor>],
) -> io::Result<u64> {
    let decoder = MultiGzDecoder::new(compressed);
    let records = warc_parser::WarcRecordIter::new(BufReader::new(decoder), format.record_type());
    let mut records_scanned = 0;

    for record in records {
        let record = record?;
        // The `PageRecord` borrows the record's own buffers: nothing is
        // copied, and it is dropped before the next record is read.
        if let Some(page) = to_page_record(format, &record.target_uri, &record.date, &record.body) {
            hand_over(&page, shard, extractors, &mut records_scanned);
        }
    }

    Ok(records_scanned)
}

/// Parse an Archive through memory-mapped I/O.
///
/// ## How mmap works here
///
/// Archives are gzip-compressed, and gzip is a streaming format —
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
///
/// ## A copy without a name
///
/// The copy is created under a name of its own, `<file name>.<process
/// id>.mmap` next to the Archive, and that name is removed at once, before a
/// single byte is written. On Unix, removing a name (`unlink`) doesn't touch
/// the file itself: the kernel frees a file once it has no name left *and*
/// nothing holds it open or mapped. Until then the open `File` still reads,
/// writes and maps it. So:
///
/// - no other process can open the copy: it has no name to open it by. Two
///   processes parsing the same Archive from one `download/` each map their
///   own, and neither can truncate the other's under its mapping (reading a
///   mapped page past the end of a truncated file kills the process with
///   `SIGBUS`);
/// - its space is freed when the function returns, on success or error,
///   and when the process is killed too: the kernel closes a dead
///   process's files and mappings, and nothing is left behind in
///   `download/`.
///
/// `OpenOptions::create_new` fails if the name exists rather than opening
/// the file there. The process id makes the name unique on one machine;
/// machines sharing `download/` over a network filesystem could pick the
/// same id at the same instant, and then the second gets an error instead
/// of the first one's bytes.
///
/// On network filesystems the space is freed the same way. An NFS client
/// renames a removed but still open file to a hidden `.nfsXXXX` (which
/// `ls -a` shows, under a name no other run looks for) and removes it once
/// the file is closed, after a kill too: only a crash of the machine itself
/// leaves one behind. Lustre and GPFS keep such files on their servers.
///
/// Windows can't remove an open file: there the copy keeps its name until
/// the function returns (`TempFile`), and a killed process leaves it
/// behind.
fn parse_mmap(
    path: &Path,
    format: Format,
    shard: &Shard,
    extractors: &mut [Box<dyn Extractor>],
) -> Result<u64, Box<dyn Error + Send + Sync>> {
    let filename = path.file_name().unwrap_or_default().to_string_lossy();
    let copy_path = with_suffix(path, &format!(".{}.mmap", process::id()));

    // Windows only: the guard removing the copy's name when this function
    // returns, by `?` on an error too. Locals are dropped in reverse order
    // of declaration: `_copy_name` first declared, last dropped, after the
    // mapping and the file it maps are closed. It is assigned only once
    // `create_new` succeeded, so it never removes a file another process
    // created; a variable never assigned is never dropped.
    #[cfg(not(unix))]
    let _copy_name: TempFile;

    eprintln!("  [{}] Decompressing to temp file for mmap...", filename);
    let mut copy = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&copy_path)?;
    #[cfg(unix)]
    fs::remove_file(&copy_path)?;
    #[cfg(not(unix))]
    {
        _copy_name = TempFile::new(copy_path);
    }
    io::copy(&mut MultiGzDecoder::new(fs::File::open(path)?), &mut copy)?;
    let copy_size = copy.metadata()?.len();
    eprintln!(
        "  [{}] Decompressed: {:.1} MB",
        filename,
        copy_size as f64 / 1_048_576.0
    );

    // `unsafe`: the mapping assumes no one changes the file while it is
    // mapped. Without a name, no other process can open the copy to do so.
    let mmap = unsafe { memmap2::Mmap::map(&copy)? };
    let mut records_scanned = 0;

    for record in warc_parser::WarcSliceIter::new(&mmap, format.record_type()) {
        // The slice parser returns raw header bytes; extractors want `&str`.
        // `from_utf8_lossy` returns a `Cow`: it borrows when the bytes are
        // valid UTF-8 (the usual case) and allocates only to replace
        // invalid ones.
        let page_url = String::from_utf8_lossy(record.target_uri);
        let date = String::from_utf8_lossy(record.date);
        if let Some(page) = to_page_record(format, &page_url, &date, record.body) {
            hand_over(&page, shard, extractors, &mut records_scanned);
        }
    }

    Ok(records_scanned)
}

/// The page one record of a `format` Archive holds: its `body` (the bytes
/// after the WARC headers) is the HTTP response in WARC, a JSON document in
/// WAT, the page's text in WET.
///
/// `None` for a WAT record that describes no page: one made from a WARC
/// `request` or `metadata` record, or one whose JSON can't be read. Such a
/// record has no crawl date to give a Sighting, so it is skipped.
fn to_page_record<'a>(
    format: Format,
    page_url: &'a str,
    date: &'a str,
    body: &'a [u8],
) -> Option<PageRecord<'a>> {
    match format {
        Format::Warc => Some(PageRecord::Warc(WarcResponse {
            page_url,
            date,
            http_response: body,
        })),
        // `date` is when the WAT was generated: the crawl date is read
        // from the JSON.
        Format::Wat => WatMetadata::parse(page_url, body).map(PageRecord::Wat),
        Format::Wet => Some(PageRecord::Wet(WetConversion {
            page_url,
            date,
            text: body,
        })),
    }
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
/// `processed.log` holds one `<shard> <kind>` line per done pair,
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
    let mut file = OpenOptions::new().append(true).create(true).open(path)?;
    writeln!(file, "{} {}", shard, kind)
}

/// Save `kind`'s Findings, then record `shard` as done for `kind`.
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
    findings: &Findings,
    shard: &Shard,
    output_dir: &str,
) -> Result<(), Box<dyn Error>> {
    save_sightings_to(kind, findings, output_dir)?;
    mark_processed_in(shard, kind, output_dir)
        .map_err(|err| format!("saved, but could not mark {} {}: {}", shard, kind, err))?;
    Ok(())
}

/// Load `kind`'s saved Findings from `output_dir`.
pub fn load_sightings_from(
    kind: ArtifactKind,
    output_dir: &str,
) -> Result<Findings, Box<dyn Error>> {
    load_sightings(kind, &Path::new(output_dir).join(kind.output_filename()))
}

/// Load `kind`'s Findings saved in `path`; a missing file means none yet.
///
/// ## Why an unreadable file is an error, not an empty map
///
/// The crawl merges new Sightings into what this returns and saves the
/// result over the same file. Returning an empty map for a file it can't
/// read (corrupt, or written in an older format such as `url` / `archive`
/// instead of `page_url` / `shard`) would make that save silently replace
/// the file's contents. Failing here stops the run before anything is
/// written.
fn load_sightings(kind: ArtifactKind, path: &Path) -> Result<Findings, Box<dyn Error>> {
    if !path.exists() {
        return Ok(Findings::empty(kind));
    }
    // `map_err` adds the path to the message: serde's error alone says
    // "missing field `page_url` at line 4" without naming the file.
    let content = fs::read_to_string(path)
        .map_err(|err| format!("cannot read {}: {}", path.display(), err))?;
    let findings = Findings::from_json(kind, &content)
        .map_err(|err| format!("cannot load {}: {}", path.display(), err))?;
    Ok(findings)
}

/// Save `kind`'s Findings to its file in `output_dir`.
///
/// ## Write, then rename
///
/// `fs::write` straight to the results file would empty it first and then
/// write the new JSON: a process killed in between (a time limit, the OOM
/// killer, Ctrl-C) would leave a cut-off file, which the next run refuses to
/// load. So the JSON is written in full to `<file>.tmp`, then renamed over
/// the results file.
///
/// On Unix, `fs::rename` replaces the target in one step: any reader, or a
/// run started after a kill, sees either the old file or the new one, never
/// a mix. That holds only within one filesystem, where a rename just changes
/// which file the name points to; across filesystems it fails. Hence the
/// temporary file sits in the same directory as the results file.
///
/// The target is a killed process, not a power cut: no `fsync`, which on a
/// network filesystem would wait for the server to store hundreds of MB on
/// every save. A leftover `<file>.tmp` is never loaded, and the next save
/// replaces it.
pub fn save_sightings_to(
    kind: ArtifactKind,
    findings: &Findings,
    output_dir: &str,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(output_dir)?;
    let path = Path::new(output_dir).join(kind.output_filename());
    let json = serde_json::to_string_pretty(findings)?;
    let temporary = TempFile::new(with_suffix(&path, ".tmp"));
    fs::write(temporary.path(), json)
        .and_then(|()| fs::rename(temporary.path(), &path))
        .map_err(|err| format!("cannot write {}: {}", path.display(), err))?;
    temporary.keep();
    Ok(())
}

/// Merge `kind`'s Findings saved in several output directories into one
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
pub fn merge_sightings_from(kind: ArtifactKind, input_dirs: &[PathBuf]) -> Option<Findings> {
    let mut merged: Option<Findings> = None;

    for dir in input_dirs {
        let path = dir.join(kind.output_filename());
        if !path.exists() {
            continue;
        }
        match load_sightings(kind, &path) {
            // `get_or_insert_with` creates the map the first time a file
            // is found, which is what turns `None` into `Some`.
            Ok(partial) => merged
                .get_or_insert_with(|| Findings::empty(kind))
                .merge(partial),
            Err(err) => eprintln!("Warning: {}, skipping it", err),
        }
    }

    merged
}
