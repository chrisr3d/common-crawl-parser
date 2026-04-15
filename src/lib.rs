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

pub mod favicon_search;
pub mod onion_search;
pub mod warc_parser;

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, BufReader, Cursor, Write};
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

/// Metadata about a favicon found on a crawled page.
///
/// Each favicon URL maps to a list of `FaviconSource` entries — the pages
/// that reference it. An inline favicon (base64 `data:` URI) is stored
/// with the decoded bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FaviconSource {
    /// The page URL where this favicon reference was found.
    pub page_url: String,
    /// Crawl timestamp from the WARC record.
    pub date: String,
    /// Which WARC archive contained this page.
    pub archive: String,
}

/// Combined result from parsing a single WARC archive.
///
/// Holds both `.onion` addresses and favicon references found during
/// a single pass over the archive. Returned by all `parse_warc_*` functions.
pub struct ParseResult {
    pub onions: HashMap<String, Vec<OnionSource>>,
    /// Favicon URLs → list of pages that reference them.
    pub favicon_urls: HashMap<String, Vec<FaviconSource>>,
    /// Inline (base64) favicons: SHA-256 hex hash → (decoded bytes, sources).
    pub inline_favicons: HashMap<String, (Vec<u8>, Vec<FaviconSource>)>,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Base URL for Common Crawl data archives.
const COMMONCRAWL_BASE: &str = "https://data.commoncrawl.org/";

/// Default directory for output files.
pub const DEFAULT_OUTPUT_DIR: &str = "output";

/// Filename for the processed-archives log.
pub const PROCESSED_FILENAME: &str = "processed.log";

/// Filename for the extracted .onion results.
pub const RESULTS_FILENAME: &str = "onions.json";

/// Filename for extracted favicon references.
pub const FAVICONS_FILENAME: &str = "favicons.json";

/// File tracking which archives have been fully processed.
pub const PROCESSED_FILE: &str = "output/processed.log";

/// JSON file storing extracted .onion addresses and their source archives.
pub const RESULTS_FILE: &str = "output/onions.json";

// ---------------------------------------------------------------------------
// HTTP Response Helpers
// ---------------------------------------------------------------------------

/// Split a WARC response body into HTTP headers and HTTP body.
///
/// WARC "response" records contain the full HTTP response:
/// ```text
/// HTTP/1.1 200 OK\r\n
/// Content-Type: text/html\r\n
/// \r\n
/// <html>...</html>
/// ```
///
/// We need the HTTP body (the HTML) for favicon extraction, and the
/// HTTP headers to check Content-Type. Returns `None` if no `\r\n\r\n`
/// separator is found (malformed response).
fn split_http_response(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let separator = memmem::find(data, b"\r\n\r\n")?;
    Some((&data[..separator], &data[separator + 4..]))
}

/// Check if HTTP headers indicate an HTML content type.
///
/// Looks for `Content-Type:` header containing `text/html` or `application/xhtml`.
/// Case-insensitive to handle the variety of web servers in the wild.
fn is_html_content(http_headers: &[u8]) -> bool {
    // Search for "content-type:" case-insensitively by scanning lines.
    for line in http_headers.split(|&b| b == b'\n') {
        let trimmed = if line.last() == Some(&b'\r') {
            &line[..line.len() - 1]
        } else {
            line
        };
        if trimmed.len() > 13
            && trimmed[..13].eq_ignore_ascii_case(b"content-type:")
        {
            let value = &trimmed[13..];
            // Check for text/html or application/xhtml anywhere in the value
            // (it may include charset, e.g. "text/html; charset=utf-8").
            let lower: Vec<u8> = value.iter().map(|b| b.to_ascii_lowercase()).collect();
            return lower.windows(9).any(|w| w == b"text/html")
                || lower.windows(16).any(|w| w == b"application/xhtml");
        }
    }
    false
}

/// Run favicon extraction on a WARC response body, if it's HTML.
///
/// Splits the HTTP response, checks Content-Type, and runs the favicon
/// scanner on the HTML body. Collects results into the provided maps.
fn extract_favicons_from_record(
    warc_body: &[u8],
    page_url: &str,
    favicon_source: &FaviconSource,
    favicon_urls: &mut HashMap<String, Vec<FaviconSource>>,
    inline_favicons: &mut HashMap<String, (Vec<u8>, Vec<FaviconSource>)>,
) {
    let Some((http_headers, http_body)) = split_http_response(warc_body) else {
        return;
    };

    if !is_html_content(http_headers) {
        return;
    }

    let result = favicon_search::extract_favicons(http_body, page_url);

    // Collect favicon URLs
    for url in result.urls {
        let sources = favicon_urls.entry(url).or_default();
        if !sources.iter().any(|s| s.page_url == favicon_source.page_url && s.archive == favicon_source.archive) {
            sources.push(favicon_source.clone());
        }
    }

    // Collect inline favicons, keyed by content hash for deduplication.
    for data in result.inline_favicons {
        let hex = hash_bytes_hex(&data);
        let entry = inline_favicons.entry(hex).or_insert_with(|| (data, Vec::new()));
        if !entry.1.iter().any(|s| s.page_url == favicon_source.page_url && s.archive == favicon_source.archive) {
            entry.1.push(favicon_source.clone());
        }
    }
}

/// Compute a hex digest of a byte slice for deduplication.
///
/// Uses `DefaultHasher` (SipHash) — not cryptographic, but sufficient
/// for deduplicating inline favicons within a crawl. We avoid adding
/// a SHA-256 crate dependency for this single use case.
fn hash_bytes_hex(data: &[u8]) -> String {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    let h1 = hasher.finish();
    // Double-hash for a 128-bit key to reduce collision risk.
    let mut hasher2 = DefaultHasher::new();
    h1.hash(&mut hasher2);
    data.len().hash(&mut hasher2);
    let h2 = hasher2.finish();
    format!("{:016x}{:016x}", h1, h2)
}

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

/// Download a WARC archive into memory instead of to disk.
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
/// Each archive is ~800 MB compressed. With `-j 4`, that's ~3.2 GB of RAM.
/// This is acceptable for modern machines and comparable to what the `mmap`
/// strategy uses in virtual memory. The benefit is zero disk usage in the
/// `download/` directory.
pub async fn download_warc_to_memory(
    client: &reqwest::Client,
    uri: &str
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let url = format!("{}{}", COMMONCRAWL_BASE, uri);
    let filename = filename_from_uri(uri).map_err(|e| -> Box<dyn Error + Send + Sync> {
        e.into()
    })?;

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
pub fn parse_warc(path: &Path, onion_re: &Regex) -> Result<ParseResult, Box<dyn Error + Send + Sync>> {
    let reader = WarcReader::from_path_gzip(path)?;
    let mut onions: HashMap<String, Vec<OnionSource>> = HashMap::new();
    let mut favicon_urls: HashMap<String, Vec<FaviconSource>> = HashMap::new();
    let mut inline_favicons: HashMap<String, (Vec<u8>, Vec<FaviconSource>)> = HashMap::new();
    let mut records_scanned: u64 = 0;
    let filename = path.file_name().unwrap_or_default().to_string_lossy();
    let archive = filename.to_string();

    for result in reader.iter_records() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue
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
            url: target_uri.clone(),
            date: date.clone(),
            archive: archive.clone()
        };

        let body = record.body();

        // Onion search
        let body_str = String::from_utf8_lossy(body);
        for m in onion_re.find_iter(&body_str) {
            let key = m.as_str().to_lowercase();
            let sources = onions.entry(key).or_default();
            if !sources.iter().any(|s| s.url == source.url && s.archive == source.archive) {
                sources.push(source.clone());
            }
        }

        // Favicon extraction
        let fav_source = FaviconSource {
            page_url: target_uri,
            date,
            archive: archive.clone(),
        };
        extract_favicons_from_record(body, &fav_source.page_url, &fav_source, &mut favicon_urls, &mut inline_favicons);

        if records_scanned % 10_000 == 0 {
            eprint!(
                "\r  [{}] Scanning: {} records, {} onion(s), {} favicon(s)",
                filename, records_scanned, onions.len(), favicon_urls.len()
            );
        }
    }

    if records_scanned >= 10_000 {
        eprintln!();
    }

    Ok(ParseResult { onions, favicon_urls, inline_favicons })
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
pub fn parse_warc_bytes(path: &Path) -> Result<ParseResult, Box<dyn Error + Send + Sync>> {
    let file = fs::File::open(path)?;
    let decoder = MultiGzDecoder::new(file);
    let buf_reader = BufReader::new(decoder);
    let iter = warc_parser::WarcRecordIter::new(buf_reader);

    let onion_re = regex::bytes::Regex::new(r"\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b")?;
    let mut onions: HashMap<String, Vec<OnionSource>> = HashMap::new();
    let mut favicon_urls: HashMap<String, Vec<FaviconSource>> = HashMap::new();
    let mut inline_favicons: HashMap<String, (Vec<u8>, Vec<FaviconSource>)> = HashMap::new();
    let mut records_scanned: u64 = 0;
    let filename = path.file_name().unwrap_or_default().to_string_lossy();
    let archive = filename.to_string();

    for result in iter {
        let record = result?;
        records_scanned += 1;

        let source = OnionSource {
            url: record.target_uri.clone(),
            date: record.date.clone(),
            archive: archive.clone()
        };
        onion_search::search_regex_bytes(&record.body, &onion_re, &source, &mut onions);

        let fav_source = FaviconSource {
            page_url: record.target_uri,
            date: record.date,
            archive: archive.clone(),
        };
        extract_favicons_from_record(&record.body, &fav_source.page_url, &fav_source, &mut favicon_urls, &mut inline_favicons);

        if records_scanned % 10_000 == 0 {
            eprint!(
                "\r  [{}] Scanning (bytes): {} records, {} onion(s), {} favicon(s)",
                filename, records_scanned, onions.len(), favicon_urls.len()
            );
        }
    }

    if records_scanned >= 10_000 {
        eprintln!();
    }

    Ok(ParseResult { onions, favicon_urls, inline_favicons })
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
pub fn parse_warc_memchr(path: &Path) -> Result<ParseResult, Box<dyn Error + Send + Sync>> {
    let file = fs::File::open(path)?;
    let decoder = MultiGzDecoder::new(file);
    let buf_reader = BufReader::new(decoder);
    let iter = warc_parser::WarcRecordIter::new(buf_reader);

    let finder = memmem::Finder::new(b".onion");
    let mut onions: HashMap<String, Vec<OnionSource>> = HashMap::new();
    let mut favicon_urls: HashMap<String, Vec<FaviconSource>> = HashMap::new();
    let mut inline_favicons: HashMap<String, (Vec<u8>, Vec<FaviconSource>)> = HashMap::new();
    let mut records_scanned: u64 = 0;
    let filename = path.file_name().unwrap_or_default().to_string_lossy();
    let archive = filename.to_string();

    for result in iter {
        let record = result?;
        records_scanned += 1;

        let source = OnionSource {
            url: record.target_uri.clone(),
            date: record.date.clone(),
            archive: archive.clone()
        };
        onion_search::search_memchr(&record.body, &finder, &source, &mut onions);

        let fav_source = FaviconSource {
            page_url: record.target_uri,
            date: record.date,
            archive: archive.clone(),
        };
        extract_favicons_from_record(&record.body, &fav_source.page_url, &fav_source, &mut favicon_urls, &mut inline_favicons);

        if records_scanned % 10_000 == 0 {
            eprint!(
                "\r  [{}] Scanning (memchr): {} records, {} onion(s), {} favicon(s)",
                filename, records_scanned, onions.len(), favicon_urls.len()
            );
        }
    }

    if records_scanned >= 10_000 {
        eprintln!();
    }

    Ok(ParseResult { onions, favicon_urls, inline_favicons })
}

/// Parse a WARC archive from an in-memory buffer using `regex::bytes`.
///
/// ## `std::io::Cursor` — the adapter pattern
///
/// `Cursor<Vec<u8>>` wraps a byte vector and implements the `Read` trait,
/// making it interchangeable with a `File`. This is Rust's adapter pattern:
/// `MultiGzDecoder` doesn't care whether its inner `Read` is a file on disk
/// or bytes in memory — it just calls `.read()`. Same interface, different
/// backing store.
///
/// ## Ownership transfer
///
/// The `data: Vec<u8>` parameter takes ownership of the buffer. When this
/// function is called from `spawn_blocking(move || ...)`, the ~800 MB
/// buffer is *moved* (zero-copy) from the async task to the blocking thread.
/// After the move, the async task no longer owns the buffer, and the compiler
/// prevents use-after-move at compile time.
pub fn parse_warc_bytes_from_memory(data: Vec<u8>, archive_name: &str) -> Result<ParseResult, Box<dyn Error + Send + Sync>> {
    let cursor = Cursor::new(data);
    let decoder = MultiGzDecoder::new(cursor);
    let buf_reader = BufReader::new(decoder);
    let iter = warc_parser::WarcRecordIter::new(buf_reader);

    let onion_re = regex::bytes::Regex::new(r"\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b")?;
    let mut onions: HashMap<String, Vec<OnionSource>> = HashMap::new();
    let mut favicon_urls: HashMap<String, Vec<FaviconSource>> = HashMap::new();
    let mut inline_favicons: HashMap<String, (Vec<u8>, Vec<FaviconSource>)> = HashMap::new();
    let mut records_scanned: u64 = 0;
    let archive = archive_name.to_string();

    for result in iter {
        let record = result?;
        records_scanned += 1;

        let source = OnionSource {
            url: record.target_uri.clone(),
            date: record.date.clone(),
            archive: archive.clone()
        };
        onion_search::search_regex_bytes(&record.body, &onion_re, &source, &mut onions);

        let fav_source = FaviconSource {
            page_url: record.target_uri,
            date: record.date,
            archive: archive.clone(),
        };
        extract_favicons_from_record(&record.body, &fav_source.page_url, &fav_source, &mut favicon_urls, &mut inline_favicons);

        if records_scanned % 10_000 == 0 {
            eprint!(
                "\r  [{}] Scanning (bytes/stream): {} records, {} onion(s), {} favicon(s)",
                archive_name, records_scanned, onions.len(), favicon_urls.len()
            );
        }
    }

    if records_scanned >= 10_000 {
        eprintln!();
    }

    Ok(ParseResult { onions, favicon_urls, inline_favicons })
}

/// Parse a WARC archive from an in-memory buffer using SIMD `memmem` search.
///
/// Same as `parse_warc_memchr` but reads from `Cursor<Vec<u8>>` instead of
/// a file on disk. See `parse_warc_bytes_from_memory` for the `Cursor`
/// explanation.
pub fn parse_warc_memchr_from_memory(data: Vec<u8>, archive_name: &str) -> Result<ParseResult, Box<dyn Error + Send + Sync>> {
    let cursor = Cursor::new(data);
    let decoder = MultiGzDecoder::new(cursor);
    let buf_reader = BufReader::new(decoder);
    let iter = warc_parser::WarcRecordIter::new(buf_reader);

    let finder = memmem::Finder::new(b".onion");
    let mut onions: HashMap<String, Vec<OnionSource>> = HashMap::new();
    let mut favicon_urls: HashMap<String, Vec<FaviconSource>> = HashMap::new();
    let mut inline_favicons: HashMap<String, (Vec<u8>, Vec<FaviconSource>)> = HashMap::new();
    let mut records_scanned: u64 = 0;
    let archive = archive_name.to_string();

    for result in iter {
        let record = result?;
        records_scanned += 1;

        let source = OnionSource {
            url: record.target_uri.clone(),
            date: record.date.clone(),
            archive: archive.clone()
        };
        onion_search::search_memchr(&record.body, &finder, &source, &mut onions);

        let fav_source = FaviconSource {
            page_url: record.target_uri,
            date: record.date,
            archive: archive.clone(),
        };
        extract_favicons_from_record(&record.body, &fav_source.page_url, &fav_source, &mut favicon_urls, &mut inline_favicons);

        if records_scanned % 10_000 == 0 {
            eprint!(
                "\r  [{}] Scanning (memchr/stream): {} records, {} onion(s), {} favicon(s)",
                archive_name, records_scanned, onions.len(), favicon_urls.len()
            );
        }
    }

    if records_scanned >= 10_000 {
        eprintln!();
    }

    Ok(ParseResult { onions, favicon_urls, inline_favicons })
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
pub fn parse_warc_mmap(path: &Path) -> Result<ParseResult, Box<dyn Error + Send + Sync>> {
    let filename = path.file_name().unwrap_or_default().to_string_lossy();
    let archive = filename.to_string();

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

    let iter = warc_parser::WarcSliceIter::new(&mmap);
    let finder = memmem::Finder::new(b".onion");
    let mut onions: HashMap<String, Vec<OnionSource>> = HashMap::new();
    let mut favicon_urls: HashMap<String, Vec<FaviconSource>> = HashMap::new();
    let mut inline_favicons: HashMap<String, (Vec<u8>, Vec<FaviconSource>)> = HashMap::new();
    let mut records_scanned: u64 = 0;

    for record in iter {
        records_scanned += 1;

        let uri = String::from_utf8_lossy(record.target_uri).to_string();
        let date = String::from_utf8_lossy(record.date).to_string();
        let source = OnionSource {
            url: uri.clone(),
            date: date.clone(),
            archive: archive.clone()
        };
        onion_search::search_memchr(record.body, &finder, &source, &mut onions);

        let fav_source = FaviconSource {
            page_url: uri,
            date,
            archive: archive.clone(),
        };
        extract_favicons_from_record(record.body, &fav_source.page_url, &fav_source, &mut favicon_urls, &mut inline_favicons);

        if records_scanned % 10_000 == 0 {
            eprint!(
                "\r  [{}] Scanning (mmap): {} records, {} onion(s), {} favicon(s)",
                filename, records_scanned, onions.len(), favicon_urls.len()
            );
        }
    }

    if records_scanned >= 10_000 {
        eprintln!();
    }

    drop(mmap);
    drop(tmp_file);
    if let Err(e) = fs::remove_file(&tmp_path) {
        eprintln!("  [{}] Warning: could not remove temp file: {}", filename, e);
    }

    Ok(ParseResult { onions, favicon_urls, inline_favicons })
}

// ---------------------------------------------------------------------------
// State Management
// ---------------------------------------------------------------------------

/// Load the set of already-processed archive filenames.
///
/// `HashSet` stores unique values with O(1) average-case lookup via hashing.
/// It's the right tool when the core question is "have we seen this before?"
pub fn load_processed() -> HashSet<String> {
    load_processed_from(DEFAULT_OUTPUT_DIR)
}

/// Load processed archives from a custom output directory.
///
/// ## HPC / batch mode
///
/// When running as a SLURM array job, each task uses its own output directory
/// (`--output-dir output/42/`) so concurrent jobs never contend on the same
/// files. This variant accepts the directory path instead of using the default.
pub fn load_processed_from(output_dir: &str) -> HashSet<String> {
    let path = Path::new(output_dir).join(PROCESSED_FILENAME);
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
    mark_processed_in(filename, DEFAULT_OUTPUT_DIR)
}

/// Append a filename to the processed log in a custom output directory.
pub fn mark_processed_in(filename: &str, output_dir: &str) -> io::Result<()> {
    fs::create_dir_all(output_dir)?;
    let path = Path::new(output_dir).join(PROCESSED_FILENAME);
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)?;
    writeln!(file, "{}", filename)
}

/// Load existing results from the JSON file.
///
/// Supports both the new format (`HashMap<String, Vec<OnionSource>>`) and
/// falls back to an empty map if the file contains the old format or is invalid.
pub fn load_results() -> HashMap<String, Vec<OnionSource>> {
    load_results_from(DEFAULT_OUTPUT_DIR)
}

/// Load results from a custom output directory.
pub fn load_results_from(output_dir: &str) -> HashMap<String, Vec<OnionSource>> {
    let path = Path::new(output_dir).join(RESULTS_FILENAME);
    if !path.exists() {
        return HashMap::new();
    }

    let content = fs::read_to_string(path).unwrap_or_default();
    serde_json::from_str(&content).unwrap_or_default()
}

/// Save the results map to the JSON file.
pub fn save_results(results: &HashMap<String, Vec<OnionSource>>) -> Result<(), Box<dyn Error>> {
    save_results_to(results, DEFAULT_OUTPUT_DIR)
}

/// Save results to a custom output directory.
pub fn save_results_to(
    results: &HashMap<String, Vec<OnionSource>>,
    output_dir: &str,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(output_dir)?;
    let path = Path::new(output_dir).join(RESULTS_FILENAME);
    let json = serde_json::to_string_pretty(results)?;
    fs::write(path, json)?;
    Ok(())
}

/// Merge multiple result files into a single deduplicated result map.
///
/// ## HPC merge step
///
/// After a SLURM array job completes, each task has produced its own
/// `onions.json` in a separate output directory. This function reads all
/// of them and merges into a single map, deduplicating on `(url, archive)`
/// pairs — the same logic used during per-archive merging in `main`.
pub fn merge_results(
    input_dirs: &[PathBuf],
) -> HashMap<String, Vec<OnionSource>> {
    let mut merged: HashMap<String, Vec<OnionSource>> = HashMap::new();

    for dir in input_dirs {
        let path = dir.join(RESULTS_FILENAME);
        if !path.exists() {
            eprintln!("Warning: no results file in {}", dir.display());
            continue;
        }
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(err) => {
                eprintln!("Warning: cannot read {}: {}", path.display(), err);
                continue;
            }
        };
        let partial: HashMap<String, Vec<OnionSource>> =
            match serde_json::from_str(&content) {
                Ok(m) => m,
                Err(err) => {
                    eprintln!("Warning: invalid JSON in {}: {}", path.display(), err);
                    continue;
                }
            };

        for (onion, sources) in partial {
            let existing = merged.entry(onion).or_default();
            for source in sources {
                if !existing.iter().any(|s| s.url == source.url && s.archive == source.archive) {
                    existing.push(source);
                }
            }
        }
    }

    merged
}

// ---------------------------------------------------------------------------
// Favicon State Management
// ---------------------------------------------------------------------------

/// Load existing favicon results from a custom output directory.
pub fn load_favicons_from(output_dir: &str) -> HashMap<String, Vec<FaviconSource>> {
    let path = Path::new(output_dir).join(FAVICONS_FILENAME);
    if !path.exists() {
        return HashMap::new();
    }
    let content = fs::read_to_string(path).unwrap_or_default();
    serde_json::from_str(&content).unwrap_or_default()
}

/// Save favicon URL results to a custom output directory.
pub fn save_favicons_to(
    favicons: &HashMap<String, Vec<FaviconSource>>,
    output_dir: &str,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(output_dir)?;
    let path = Path::new(output_dir).join(FAVICONS_FILENAME);
    let json = serde_json::to_string_pretty(favicons)?;
    fs::write(path, json)?;
    Ok(())
}

/// Merge favicon results from multiple output directories.
pub fn merge_favicons(input_dirs: &[PathBuf]) -> HashMap<String, Vec<FaviconSource>> {
    let mut merged: HashMap<String, Vec<FaviconSource>> = HashMap::new();

    for dir in input_dirs {
        let path = dir.join(FAVICONS_FILENAME);
        if !path.exists() {
            continue;
        }
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(err) => {
                eprintln!("Warning: cannot read {}: {}", path.display(), err);
                continue;
            }
        };
        let partial: HashMap<String, Vec<FaviconSource>> =
            match serde_json::from_str(&content) {
                Ok(m) => m,
                Err(err) => {
                    eprintln!("Warning: invalid JSON in {}: {}", path.display(), err);
                    continue;
                }
            };

        for (url, sources) in partial {
            let existing = merged.entry(url).or_default();
            for source in sources {
                if !existing.iter().any(|s| s.page_url == source.page_url && s.archive == source.archive) {
                    existing.push(source);
                }
            }
        }
    }

    merged
}
