// onion-crawler library — download, parsing, and state management
//
// This module contains all the feature-specific code:
//   - Downloading WARC archives from Common Crawl (async with reqwest)
//   - Parsing WARC records and extracting .onion addresses (multiple strategies)
//   - Persistent state: processed log and results JSON
//
// ## Parsing strategies (ripgrep-inspired optimization layers)
//
// Four strategies are available, selectable at runtime via `--strategy`:
//   - Baseline: original `warc` crate + `regex::Regex` on UTF-8 strings
//   - Bytes:    custom WARC parser + `regex::bytes::Regex` on raw &[u8]
//   - Memchr:   custom parser + SIMD `memmem` literal search (no regex)
//   - Mmap:     decompress to temp file → mmap → zero-copy memchr search

pub mod onion_search;
pub mod warc_parser;

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};

use flate2::read::MultiGzDecoder;
use memchr::memmem;
use regex::Regex;
use serde::{Deserialize, Serialize};
use warc::{RecordType, WarcReader};

// ---------------------------------------------------------------------------
// Data Types
// ---------------------------------------------------------------------------

/// Metadata about where an .onion address was found.
///
/// Each .onion address maps to a list of `OnionSource` entries, one for each
/// distinct (URL, archive) pair where it appeared. This gives us rich context:
/// not just "which archive" but "which specific clearnet page, when".
///
/// `Serialize` and `Deserialize` are derived for JSON persistence via `serde`.
/// `Clone` is needed because the same source may be referenced across multiple
/// search calls within a single record (rare, but possible with duplicates).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnionSource {
    pub url: String,
    pub date: String,
    pub archive: String,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Base URL for Common Crawl data archives.
const COMMONCRAWL_BASE: &str = "https://data.commoncrawl.org/";

/// File tracking which archives have been fully processed.
pub const PROCESSED_FILE: &str = "output/processed.log";

/// JSON file storing extracted .onion addresses and their source archives.
pub const RESULTS_FILE: &str = "output/onions.json";

// ---------------------------------------------------------------------------
// Download Logic
// ---------------------------------------------------------------------------

/// Extract the filename component from a WARC URI path.
///
/// e.g. `crawl-data/CC-NEWS/.../CC-NEWS-20251001.warc.gz` → `CC-NEWS-20251001.warc.gz`
pub fn filename_from_uri(uri: &str) -> Result<&str, &'static str> {
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
pub async fn download_warc_async(
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
pub fn parse_warc(path: &Path, onion_re: &Regex) -> Result<HashMap<String, Vec<OnionSource>>, Box<dyn Error + Send + Sync>> {
    let reader = WarcReader::from_path_gzip(path)?;
    let mut onions: HashMap<String, Vec<OnionSource>> = HashMap::new();
    let mut records_scanned: u64 = 0;
    let filename = path.file_name().unwrap_or_default().to_string_lossy();
    let archive = filename.to_string();

    for result in reader.iter_records() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };

        if *record.warc_type() != RecordType::Response {
            continue;
        }

        records_scanned += 1;

        // Extract metadata from the warc crate's parsed headers.
        let target_uri = record.header(warc::WarcHeader::TargetURI)
            .map(|v| v.to_string())
            .unwrap_or_default();
        let date = record.header(warc::WarcHeader::Date)
            .map(|v| v.to_string())
            .unwrap_or_default();
        let source = OnionSource {
            url: target_uri,
            date,
            archive: archive.clone(),
        };

        let body = String::from_utf8_lossy(record.body());
        for m in onion_re.find_iter(&body) {
            let key = m.as_str().to_lowercase();
            let sources = onions.entry(key).or_default();
            if !sources.iter().any(|s| s.url == source.url && s.archive == source.archive) {
                sources.push(source.clone());
            }
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

/// Parse a WARC archive using the custom byte-level parser + `regex::bytes`.
///
/// ## What's different from the baseline
///
/// 1. **Custom WARC parser** — skips non-response record bodies entirely
///    (the `warc` crate reads every body, even ones we discard)
/// 2. **`regex::bytes::Regex`** — searches `&[u8]` directly, no UTF-8 conversion
///    (eliminates `String::from_utf8_lossy` allocation per record)
/// 3. **`flate2` decompression** — wraps zlib for faster gzip decoding
///
/// Expected ~1.5-2x speedup over baseline.
pub fn parse_warc_bytes(path: &Path) -> Result<HashMap<String, Vec<OnionSource>>, Box<dyn Error + Send + Sync>> {
    let file = fs::File::open(path)?;
    let decoder = MultiGzDecoder::new(file);
    let buf_reader = BufReader::new(decoder);
    let iter = warc_parser::WarcRecordIter::new(buf_reader);

    let onion_re = regex::bytes::Regex::new(r"\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b")?;
    let mut onions: HashMap<String, Vec<OnionSource>> = HashMap::new();
    let mut records_scanned: u64 = 0;
    let filename = path.file_name().unwrap_or_default().to_string_lossy();
    let archive = filename.to_string();

    for result in iter {
        let record = result?;
        records_scanned += 1;

        let source = OnionSource {
            url: record.target_uri,
            date: record.date,
            archive: archive.clone(),
        };
        onion_search::search_regex_bytes(&record.body, &onion_re, &source, &mut onions);

        if records_scanned % 10_000 == 0 {
            eprint!(
                "\r  [{}] Scanning (bytes): {} records, {} onion(s)",
                filename, records_scanned, onions.len()
            );
        }
    }

    if records_scanned >= 10_000 {
        eprintln!();
    }

    Ok(onions)
}

/// Parse a WARC archive using the custom parser + SIMD `memmem` literal search.
///
/// ## The ripgrep technique
///
/// Instead of running a regex engine on every byte, we:
/// 1. Use `memmem::Finder` (SIMD-accelerated) to jump to ".onion" literals
/// 2. Validate surrounding bytes with cheap comparisons
///
/// `memmem` scans 16-32 bytes per CPU cycle via SIMD. Since ".onion" is
/// rare in typical web content, the validator almost never runs. This is
/// dramatically faster than the regex NFA which must track state for every byte.
///
/// Expected ~3-5x speedup over baseline.
pub fn parse_warc_memchr(path: &Path) -> Result<HashMap<String, Vec<OnionSource>>, Box<dyn Error + Send + Sync>> {
    let file = fs::File::open(path)?;
    let decoder = MultiGzDecoder::new(file);
    let buf_reader = BufReader::new(decoder);
    let iter = warc_parser::WarcRecordIter::new(buf_reader);

    let finder = memmem::Finder::new(b".onion");
    let mut onions: HashMap<String, Vec<OnionSource>> = HashMap::new();
    let mut records_scanned: u64 = 0;
    let filename = path.file_name().unwrap_or_default().to_string_lossy();
    let archive = filename.to_string();

    for result in iter {
        let record = result?;
        records_scanned += 1;

        let source = OnionSource {
            url: record.target_uri,
            date: record.date,
            archive: archive.clone(),
        };
        onion_search::search_memchr(&record.body, &finder, &source, &mut onions);

        if records_scanned % 10_000 == 0 {
            eprint!(
                "\r  [{}] Scanning (memchr): {} records, {} onion(s)",
                filename, records_scanned, onions.len()
            );
        }
    }

    if records_scanned >= 10_000 {
        eprintln!();
    }

    Ok(onions)
}

/// Parse a WARC archive using memory-mapped I/O + SIMD literal search.
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
/// ~3-5GB on disk. For machines with enough disk space, this is the
/// fastest approach.
///
/// Expected ~3-6x speedup over baseline.
pub fn parse_warc_mmap(path: &Path) -> Result<HashMap<String, Vec<OnionSource>>, Box<dyn Error + Send + Sync>> {
    let filename = path.file_name().unwrap_or_default().to_string_lossy();
    let archive = filename.to_string();

    // Phase 1: Decompress to a temporary file.
    // We write to download/<name>.decompressed and clean up after parsing.
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

    // Phase 2: Memory-map the decompressed file.
    let tmp_file = fs::File::open(&tmp_path)?;
    // SAFETY: memmap2::Mmap requires that the file is not modified while
    // mapped. Since we created this temp file and no other process touches
    // it, this is safe. The `unsafe` block is required by the mmap API
    // because in general, another process could modify the file.
    let mmap = unsafe { memmap2::Mmap::map(&tmp_file)? };

    // Phase 3: Parse WARC records from the memory-mapped slice.
    let iter = warc_parser::WarcSliceIter::new(&mmap);
    let finder = memmem::Finder::new(b".onion");
    let mut onions: HashMap<String, Vec<OnionSource>> = HashMap::new();
    let mut records_scanned: u64 = 0;

    for record in iter {
        records_scanned += 1;

        // Convert zero-copy byte slices to owned Strings for the source.
        let source = OnionSource {
            url: String::from_utf8_lossy(record.target_uri).to_string(),
            date: String::from_utf8_lossy(record.date).to_string(),
            archive: archive.clone(),
        };
        onion_search::search_memchr(record.body, &finder, &source, &mut onions);

        if records_scanned % 10_000 == 0 {
            eprint!(
                "\r  [{}] Scanning (mmap): {} records, {} onion(s)",
                filename, records_scanned, onions.len()
            );
        }
    }

    if records_scanned >= 10_000 {
        eprintln!();
    }

    // Phase 4: Clean up the temporary decompressed file.
    drop(mmap);
    drop(tmp_file);
    if let Err(e) = fs::remove_file(&tmp_path) {
        eprintln!("  [{}] Warning: could not remove temp file: {}", filename, e);
    }

    Ok(onions)
}

// ---------------------------------------------------------------------------
// State Management
// ---------------------------------------------------------------------------

/// Load the set of already-processed archive filenames.
///
/// `HashSet` stores unique values with O(1) average-case lookup via hashing.
/// It's the right tool when the core question is "have we seen this before?"
pub fn load_processed() -> HashSet<String> {
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
pub fn mark_processed(filename: &str) -> io::Result<()> {
    fs::create_dir_all("output")?;
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(PROCESSED_FILE)?;
    writeln!(file, "{}", filename)
}

/// Load existing results from the JSON file.
///
/// Supports both the new format (`HashMap<String, Vec<OnionSource>>`) and
/// falls back to an empty map if the file contains the old format or is invalid.
pub fn load_results() -> HashMap<String, Vec<OnionSource>> {
    let path = Path::new(RESULTS_FILE);
    if !path.exists() {
        return HashMap::new();
    }

    let content = fs::read_to_string(path).unwrap_or_default();
    serde_json::from_str(&content).unwrap_or_default()
}

/// Save the results map to the JSON file.
pub fn save_results(results: &HashMap<String, Vec<OnionSource>>) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all("output")?;
    let json = serde_json::to_string_pretty(results)?;
    fs::write(RESULTS_FILE, json)?;
    Ok(())
}
