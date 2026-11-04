// cc-extract library — download, parsing, and state management
//
// This module ties the pieces together:
//   - Downloading Archives from Common Crawl (async with reqwest)
//   - `spawn_each`: running each Shard in a task of its own, so downloads
//     go on while finished Shards are written
//   - `parse_archive`: reading every record of an Archive once and handing
//     it to each extractor
//   - The results store: Sightings and done marks in kvrocks (`store`)
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
// `parse_archive` only connects them: a new kind needs its own `Extractor`,
// but the parsing loop stays as it is.
//
// Which Formats are read for a Shard is the planner's choice (`plan`): for
// each requested kind, the Formats that find the most among those the
// Shard offers (`format` says what Common Crawl publishes and where).

pub mod artifact;
pub mod extractor;
pub mod favicon_search;
pub mod format;
pub mod inline_favicon;
pub mod onion_search;
pub mod page_record;
pub mod plan;
pub mod store;
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
pub use store::{KvrocksStore, StoreAddress};

use std::any::Any;
use std::cell::Cell;
use std::error::Error;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, BufReader, Cursor, Read};
use std::iter;
use std::panic;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::process;
use std::time::Duration;

use flate2::read::MultiGzDecoder;
use futures::stream::{self, Stream, StreamExt, TryStreamExt};
use tokio::io::AsyncWriteExt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Base URL for Common Crawl data archives.
const COMMONCRAWL_BASE: &str = "https://data.commoncrawl.org/";

// ---------------------------------------------------------------------------
// Temporary files
// ---------------------------------------------------------------------------

/// `path` with `suffix` appended to its file name: `x.warc.gz` and
/// `.part` give `x.warc.gz.part`, in the same directory.
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

/// How long the crawl's downloads wait for data before failing.
pub const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// How long connecting to the server may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// The HTTP client the downloads go through, with the read timeout it was
/// built with.
///
/// ## A download that stops receiving data fails
///
/// By default, a connected `reqwest::Client` waits for data as long as it
/// takes. A server (or something between it and us) that stops sending without
/// closing the connection would keep the download, its Shard's task and so
/// the whole run waiting forever. TCP keepalive, which `reqwest` enables,
/// only fails a connection whose peer is gone, not one whose peer still
/// answers but sends nothing.
///
/// So the client has a read timeout: a download fails when its response
/// headers haven't arrived that long after the request was sent (connecting
/// included), or when the next chunk of the body hasn't, that long after the
/// one before. The wait starts over at each chunk, so a slow download that
/// keeps receiving data is never cut, however long it takes in all; a
/// timeout on the whole request (`ClientBuilder::timeout`) would cut a slow
/// but healthy 1 GB Archive.
///
/// The client keeps the bound to say what happened (`download_error`):
/// `reqwest`'s own message, `error decoding response body` (`error sending
/// request` while waiting for the headers), doesn't.
///
/// ## Cheap to clone
///
/// `reqwest::Client` keeps its connection pool behind an `Arc`, so cloning
/// it, and this struct with it, only increments a reference count: every
/// clone shares the pool.
#[derive(Clone)]
pub struct HttpClient {
    client: reqwest::Client,
    read_timeout: Duration,
}

impl HttpClient {
    /// A client whose connections time out after 30 s, and whose reads
    /// after `read_timeout` without data. The crawl uses `READ_TIMEOUT`.
    pub fn new(read_timeout: Duration) -> reqwest::Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(read_timeout)
            .build()?;
        Ok(HttpClient {
            client,
            read_timeout,
        })
    }

    /// Request `url`, and return the response once its headers arrived. An
    /// HTTP error status (404, 503, ...) is an error.
    async fn get(&self, url: &str) -> Result<reqwest::Response, Box<dyn Error + Send + Sync>> {
        self.client
            .get(url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|err| self.download_error(err.into()))
    }

    /// `err` as a download reports it: the read timeout says that no data
    /// came, and for how long. Every other error is kept as it is.
    ///
    /// ## Looking inside a `Box<dyn Error>`
    ///
    /// `downcast_ref::<T>()` returns the error as a `&T` if it is a `T`, and
    /// `None` otherwise. `?` boxes a `reqwest::Error` as it is, so one coming
    /// back from `save_archive` is still found.
    fn download_error(&self, err: Box<dyn Error + Send + Sync>) -> Box<dyn Error + Send + Sync> {
        let timed_out = err
            .downcast_ref::<reqwest::Error>()
            .is_some_and(is_read_timeout);
        if timed_out {
            format!("no data received for {} s", self.read_timeout.as_secs_f64()).into()
        } else {
            err
        }
    }
}

/// Whether `err` is the client's read timeout.
///
/// `is_timeout` holds for any timeout found among the errors `err` wraps.
/// Two others are kept apart: the connect timeout (`is_connect`), and the
/// system's own, an `io::Error` of kind `TimedOut` (TCP keepalive or
/// retransmissions giving up), which say something else happened.
///
/// ## Walking an error's causes
///
/// `source()` returns the error this one wraps, if any. `iter::successors`
/// turns that chain into an iterator: it starts from the first value and
/// computes each next one from the one before, until `None`. The closure is
/// handed a reference to that value, itself a reference (`&&dyn Error`):
/// the `&cause` pattern copies the inner one out, so the next cause borrows
/// from `err`, not from the closure's argument, gone once it returns.
fn is_read_timeout(err: &reqwest::Error) -> bool {
    let system_timeout = iter::successors(err.source(), |&cause| cause.source()).any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|cause| cause.kind() == io::ErrorKind::TimedOut)
    });
    err.is_timeout() && !err.is_connect() && !system_timeout
}

/// Whether a download failed in a way that repeats by nature, so that
/// counts toward giving the Archive up: the server answered with a client
/// error status (4xx), such as 404 Not Found, which it will answer again.
///
/// Every other failure may not happen again, and doesn't count: 408
/// (Request Timeout) and 429 (Too Many Requests) ask to come back later, a
/// 5xx is the server's own trouble, and a timeout, a connection error, a
/// body cut short or a local file that can't be written say nothing about
/// the Archive.
///
/// `err` is a download's error as returned: a `reqwest::Error`, boxed as it
/// is, holds the status it was made from (`Response::error_for_status`).
pub fn download_failure_repeats(err: &(dyn Error + Send + Sync + 'static)) -> bool {
    let status = err
        .downcast_ref::<reqwest::Error>()
        .and_then(reqwest::Error::status);
    status.is_some_and(|status| {
        status.is_client_error()
            && status != reqwest::StatusCode::REQUEST_TIMEOUT
            && status != reqwest::StatusCode::TOO_MANY_REQUESTS
    })
}

/// Directory where the disk and mmap Transports keep downloaded Archives,
/// under the current directory.
const DOWNLOAD_DIR: &str = "download";

/// Where the disk and mmap Transports keep a downloaded Archive.
pub fn download_path(archive: &ArchivePath) -> PathBuf {
    Path::new(DOWNLOAD_DIR).join(archive.file_name())
}

/// Download one Archive from Common Crawl to `download/`, unless it is there
/// already, and return its path there (see `download_to`).
pub async fn download_archive(
    client: &HttpClient,
    archive: &ArchivePath,
) -> Result<PathBuf, Box<dyn Error + Send + Sync>> {
    let url = format!("{}{}", COMMONCRAWL_BASE, archive.uri());
    let local_path = download_path(archive);
    download_to(client, &url, &local_path).await?;
    Ok(local_path)
}

/// Download the Archive at `url` to `local_path` using async I/O, unless a
/// file is there already.
///
/// The one place that decides whether an Archive is downloaded: a file at
/// `local_path` is the Archive, complete, since `save_archive` puts one
/// there only once every byte arrived.
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
pub async fn download_to(
    client: &HttpClient,
    url: &str,
    local_path: &Path,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let filename = local_path.file_name().unwrap_or_default().to_string_lossy();

    if local_path.exists() {
        eprintln!("  [{}] Already downloaded, skipping download", filename);
        return Ok(());
    }

    // `tokio::fs::create_dir_all` is the async version of `fs::create_dir_all`.
    // For file system operations, async doesn't help much (disk I/O is fast),
    // but it avoids blocking the Tokio runtime thread.
    if let Some(dir) = local_path.parent() {
        tokio::fs::create_dir_all(dir).await?;
    }

    eprintln!("  [{}] Downloading...", filename);
    eprintln!("  [{}] URL: {}", filename, url);

    let response = client.get(url).await?;

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
    save_archive(chunks, total_size, local_path)
        .await
        .map_err(|err| client.download_error(err))
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
/// run reads.
///
/// On Unix, `rename` replaces the target in one step: a reader, or a run
/// started after a kill, sees no file or the whole Archive, never part of
/// it. That holds only within one filesystem, where a rename just changes
/// which file the name points to; across filesystems it fails. Hence the
/// partial file sits in the same directory as the Archive.
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

/// Download one Archive from Common Crawl into memory instead of to disk
/// (see `download_to_memory`).
pub async fn download_archive_to_memory(
    client: &HttpClient,
    archive: &ArchivePath,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let url = format!("{}{}", COMMONCRAWL_BASE, archive.uri());
    download_to_memory(client, &url).await
}

/// Download the Archive at `url` into memory instead of to disk.
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
pub async fn download_to_memory(
    client: &HttpClient,
    url: &str,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    // The log lines name the Archive by the URL's last component.
    let filename = url.rsplit('/').next().unwrap_or(url);

    eprintln!("  [{}] Downloading to memory...", filename);
    eprintln!("  [{}] URL: {}", filename, url);

    let mut response = client.get(url).await?;

    let total_size = response.content_length();
    if let Some(size) = total_size {
        eprintln!("  [{}] Size: {:.1} MB", filename, size as f64 / 1_048_576.0);
    }

    // Pre-allocate the buffer when the size is known, avoiding repeated
    // geometric-growth reallocations (each doubling copies all existing data).
    let mut buffer: Vec<u8> = Vec::with_capacity(total_size.unwrap_or(0) as usize);
    let mut bytes_read: u64 = 0;
    let mut last_report: u64 = 0;

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| client.download_error(err.into()))?
    {
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
// Running Shards concurrently
// ---------------------------------------------------------------------------

/// Run each of `futures` in a task of its own, at most `jobs` at once, and
/// yield their outputs as they finish, in any order.
///
/// ## Why tasks
///
/// `buffer_unordered(jobs)` alone runs the futures inside the stream: they
/// make progress only while the stream is polled, that is while its
/// consumer waits for the next output. The crawl's consumer writes each
/// finished Shard to the store in between; a download left unpolled for
/// the client's read timeout fails on its next poll, data or not. So a
/// store write lasting longer than that would fail every download in
/// flight.
///
/// `tokio::spawn` hands a future to the runtime, which runs it on its own
/// whatever the stream's consumer is doing; the stream then only waits for
/// each task's `JoinHandle`. A future is spawned when `buffer_unordered`
/// starts it, so no more than `jobs` run or wait to be taken at once, and
/// a slow consumer holds the next ones back instead of failing them.
///
/// ## `Send + 'static`
///
/// The runtime may run a task on any of its threads (`Send`) and for as
/// long as it takes, past the function that spawned it (`'static`): a
/// spawned future owns everything it uses, borrowing nothing from its
/// caller. Its output comes back across threads too.
///
/// ## A panicking task
///
/// A panic inside a task ends that task, not the process: the
/// `JoinHandle` returns it as a `JoinError`. It is resumed here, in the
/// consumer, as it would have gone on without the task: a bug, not a Shard
/// to skip quietly. (A `JoinError` can also mean the task was cancelled,
/// which none of these ever is: `into_panic` itself panics then.)
pub fn spawn_each<F>(
    futures: impl IntoIterator<Item = F>,
    jobs: usize,
) -> impl Stream<Item = F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    stream::iter(futures)
        .map(|future| async move {
            match tokio::spawn(future).await {
                Ok(output) => output,
                Err(err) => panic::resume_unwind(err.into_panic()),
            }
        })
        .buffer_unordered(jobs)
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

/// Why an Archive couldn't be parsed.
#[derive(Debug)]
pub enum ParseError {
    /// Its bytes can't be read as an Archive: not gzip, a gzip member
    /// damaged or cut short, data ending inside a record, a record whose
    /// `Content-Length` is missing or malformed. Parsing them again fails
    /// the same way.
    ///
    /// The message says where it broke, `(at byte <at> of <size>)`: whether
    /// damaged Archives break at their start, or further in, with records
    /// before and after the fault that reading on could keep.
    Corrupt {
        error: io::Error,
        /// How many compressed bytes were read when the error came: past
        /// the fault, as the gzip decoder reads 32 KiB at a time and checks
        /// a member's checksum only at its end, by up to the rest of the
        /// member and one read. A record cut short at the end of the data
        /// is found once all of them were read: then `at` is `size`.
        at: u64,
        /// The size of the compressed Archive.
        size: u64,
    },
    /// A local file couldn't be opened, read or written: the Archive in
    /// `download/` missing or unreadable, the mmap copy that can't be
    /// created, a disk full while writing it. Nothing says the Archive is
    /// bad.
    Local(io::Error),
    /// Parsing panicked, with this message: a bug in this program, that the
    /// Archive's bytes trigger. Parsing them again panics again, so it
    /// counts as `Corrupt` does, and the Archive is given up in the end
    /// instead of failing its Shard on every run.
    Panicked(String),
}

impl ParseError {
    /// Whether parsing the same bytes would fail again: such a failure
    /// counts toward giving the Archive up.
    pub fn repeats(&self) -> bool {
        matches!(self, ParseError::Corrupt { .. } | ParseError::Panicked(_))
    }

    /// The error of a parse that panicked, from the `payload` the panic
    /// carried, as `std::panic::catch_unwind` returns it.
    ///
    /// ## A panic's payload: `Box<dyn Any + Send>`
    ///
    /// `panic!` can carry any value, so `catch_unwind` hands it back as a
    /// `dyn Any`, a value whose type is only known at run time.
    /// `downcast_ref::<T>()` returns it as a `&T` if it is a `T`. A
    /// `panic!` with a plain literal carries a `&'static str`, one with
    /// values to format a `String`; any other value (`panic_any`) is named
    /// `Box<dyn Any>`, as the default panic hook prints it.
    pub fn from_panic(payload: Box<dyn Any + Send>) -> Self {
        let message = if let Some(message) = payload.downcast_ref::<&str>() {
            message.to_string()
        } else if let Some(message) = payload.downcast_ref::<String>() {
            message.clone()
        } else {
            "Box<dyn Any>".to_string()
        };
        ParseError::Panicked(message)
    }
}

/// The underlying error's message: what failed, whichever the kind, and
/// for the Archive's bytes, where.
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Corrupt { error, at, size } => {
                write!(f, "{error} (at byte {at} of {size})")
            }
            ParseError::Local(error) => error.fmt(f),
            ParseError::Panicked(message) => write!(f, "the parser panicked: {message}"),
        }
    }
}

impl Error for ParseError {}

/// A local file the parser reads or writes, whose errors are marked as its
/// own.
///
/// ## Telling apart where an error came from
///
/// Decoding stacks readers: the record parser reads the gzip decoder, which
/// reads the file. Whichever of them fails, the error comes out of the top
/// one as an `io::Error`, and a disk failing to read looks like bytes
/// failing to decode. So the file's own errors are wrapped as they leave
/// it: `io::Error::new(kind, error)` builds an `io::Error` carrying any
/// error inside, here a `LocalFileError`, and the readers above pass it up
/// as it is. Its kind is kept, so a reader retrying on `Interrupted` still
/// does. `Position::error` then looks for the mark.
struct LocalFile<T>(T);

impl<R: Read> Read for LocalFile<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf).map_err(LocalFileError::mark)
    }
}

impl<W: io::Write> io::Write for LocalFile<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf).map_err(LocalFileError::mark)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush().map_err(LocalFileError::mark)
    }
}

/// An error a `LocalFile` returned, as its mark.
#[derive(Debug)]
struct LocalFileError(io::Error);

impl LocalFileError {
    /// `err`, marked as a local file's.
    fn mark(err: io::Error) -> io::Error {
        io::Error::new(err.kind(), LocalFileError(err))
    }
}

/// The file's own message: the mark doesn't show.
impl fmt::Display for LocalFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Error for LocalFileError {}

/// How far reading a compressed Archive got: the bytes read so far, of its
/// size. A `Counted` reader under the gzip decoder adds to it; an error met
/// reading the records takes its position from it (`error`).
///
/// ## `Cell`: a count both sides can reach
///
/// The decoder takes ownership of the reader it reads, and keeps it until
/// parsing ends; the count is wanted while it still holds it, when an
/// error comes. A `&mut u64` in the reader would forbid any other access
/// to the count for as long as the decoder lives. A `Cell<u64>` can be
/// changed through a shared reference (`set`) and read through one
/// (`get`): the reader holds one `&Position`, the caller another, and the
/// borrow checker accepts both. `Cell` only hands out copies of its value,
/// never a reference into it, which is what makes this safe; it is also not
/// `Sync`, so the compiler keeps both sides on one thread.
struct Position {
    bytes_read: Cell<u64>,
    size: u64,
}

impl Position {
    /// The start of an Archive of `size` compressed bytes.
    fn new(size: u64) -> Self {
        Position {
            bytes_read: Cell::new(0),
            size,
        }
    }

    /// `compressed`, its reads counted here.
    fn count<R: Read>(&self, compressed: R) -> Counted<'_, R> {
        Counted {
            inner: compressed,
            position: self,
        }
    }

    /// `error`, met reading the Archive's records (decoding them, or
    /// finding one cut short): `Local` if a local file failed (`LocalFile`
    /// marked it), `Corrupt` at this position otherwise.
    ///
    /// `io::Error::get_ref` returns the error an `io::Error` was made from
    /// with `io::Error::new`, if any; `is::<T>()` says whether it is a `T`.
    fn error(&self, error: io::Error) -> ParseError {
        if error
            .get_ref()
            .is_some_and(|inner| inner.is::<LocalFileError>())
        {
            ParseError::Local(error)
        } else {
            ParseError::Corrupt {
                error,
                at: self.bytes_read.get(),
                size: self.size,
            }
        }
    }
}

/// A reader adding the bytes read through it to a `Position`.
struct Counted<'a, R> {
    inner: R,
    position: &'a Position,
}

impl<R: Read> Read for Counted<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        let bytes_read = &self.position.bytes_read;
        bytes_read.set(bytes_read.get() + n as u64);
        Ok(n)
    }
}

/// Read every page record of one `format` Archive once and hand it to
/// every extractor.
///
/// When this returns, each extractor holds what it found in the Archive;
/// `Extractor::into_findings` hands that over. The function itself never
/// looks at which Artifact kinds it is feeding. An error says whether the
/// Archive's bytes are to blame (`ParseError`).
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
) -> Result<(), ParseError> {
    let records_scanned = match transport {
        // `File` and `Cursor<Vec<u8>>` both implement `Read`, so one
        // streaming loop serves both. A `Cursor` never fails to read: every
        // error then comes from the bytes.
        Transport::Disk(path) => {
            let file = fs::File::open(path).map_err(ParseError::Local)?;
            let size = file.metadata().map_err(ParseError::Local)?.len();
            parse_stream(LocalFile(file), size, format, shard, extractors)?
        }
        Transport::Memory(data) => {
            let size = data.len() as u64;
            parse_stream(Cursor::new(data), size, format, shard, extractors)?
        }
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
///
/// `size` is the length of `compressed`, for the position an error gives.
fn parse_stream<R: Read>(
    compressed: R,
    size: u64,
    format: Format,
    shard: &Shard,
    extractors: &mut [Box<dyn Extractor>],
) -> Result<u64, ParseError> {
    // Declared before the readers borrowing it: locals are dropped in
    // reverse order, so it outlives them.
    let position = Position::new(size);
    let decoder = MultiGzDecoder::new(position.count(compressed));
    let records = warc_parser::WarcRecordIter::new(BufReader::new(decoder), format.record_type());
    let mut records_scanned = 0;

    for record in records {
        let record = record.map_err(|err| position.error(err))?;
        // Header bytes read as text, as in `parse_mmap`. The `PageRecord`
        // borrows the record's own buffers: nothing is copied (unless a
        // header isn't UTF-8), and it is dropped before the next record is
        // read.
        let page_url = String::from_utf8_lossy(&record.target_uri);
        let date = String::from_utf8_lossy(&record.date);
        if let Some(page) = to_page_record(format, &page_url, &date, &record.body) {
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
///
/// Decompressing and reading the records fail on the Archive's bytes
/// (`ParseError::Corrupt`): a record cut short shows only in the copy, once
/// every compressed byte was read. Every other step fails on a local file
/// (`ParseError::Local`), and so does writing the copy.
fn parse_mmap(
    path: &Path,
    format: Format,
    shard: &Shard,
    extractors: &mut [Box<dyn Extractor>],
) -> Result<u64, ParseError> {
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
        .open(&copy_path)
        .map_err(ParseError::Local)?;
    #[cfg(unix)]
    fs::remove_file(&copy_path).map_err(ParseError::Local)?;
    #[cfg(not(unix))]
    {
        _copy_name = TempFile::new(copy_path);
    }
    let archive = fs::File::open(path).map_err(ParseError::Local)?;
    let size = archive.metadata().map_err(ParseError::Local)?.len();
    let position = Position::new(size);
    io::copy(
        &mut MultiGzDecoder::new(position.count(LocalFile(archive))),
        &mut LocalFile(&mut copy),
    )
    .map_err(|err| position.error(err))?;
    let copy_size = copy.metadata().map_err(ParseError::Local)?.len();
    eprintln!(
        "  [{}] Decompressed: {:.1} MB",
        filename,
        copy_size as f64 / 1_048_576.0
    );

    // `unsafe`: the mapping assumes no one changes the file while it is
    // mapped. Without a name, no other process can open the copy to do so.
    let mmap = unsafe { memmap2::Mmap::map(&copy).map_err(ParseError::Local)? };
    let mut records_scanned = 0;

    for record in warc_parser::WarcSliceIter::new(&mmap, format.record_type()) {
        // A record cut short, found once all the compressed bytes were read.
        let record = record.map_err(|err| position.error(err))?;
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
