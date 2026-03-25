// Custom byte-level WARC parser — ripgrep-inspired optimization
//
// The `warc` crate (v0.4) parses ALL headers with nom and allocates a HashMap
// per record. For .onion extraction we only need two pieces of information:
//   1. Is this a "response" record? (WARC-Type header)
//   2. What are the body bytes? (Content-Length header + body data)
//
// By parsing only these two headers and skipping non-response bodies entirely,
// we avoid reading ~60% of the decompressed data into memory. This is the
// same philosophy ripgrep uses: do the minimum work to determine relevance,
// then only process what matters.
//
// Two parser implementations:
//   - `WarcRecordIter<R: BufRead>` — streaming parser for sequential reads
//   - `WarcSliceIter<'a>` — slice parser for memory-mapped data (zero-copy)

use std::io::{self, BufRead, Read};

use memchr::memmem;

// ---------------------------------------------------------------------------
// Streaming Parser — works with BufRead (e.g., gzip decoder + BufReader)
// ---------------------------------------------------------------------------

/// A parsed WARC response record — the fields we need for .onion extraction.
///
/// Non-response records are skipped entirely (their bodies are never read).
/// This struct only exists for records where `WARC-Type: response`.
///
/// In addition to the body, we extract metadata from WARC headers:
/// - `target_uri`: the original URL that was crawled (WARC-Target-URI header)
/// - `date`: the timestamp of the crawl (WARC-Date header)
///
/// These let us track *where* and *when* each .onion address was found,
/// not just *which archive* it appeared in.
pub struct WarcRecord {
    pub body: Vec<u8>,
    pub target_uri: String,
    pub date: String,
}

/// Iterates WARC response records from a `BufRead` source.
///
/// ## How WARC records are structured
///
/// Each record looks like:
/// ```text
/// WARC/1.0\r\n
/// WARC-Type: response\r\n
/// Content-Length: 12345\r\n
/// ... other headers ...\r\n
/// \r\n
/// <body bytes: exactly Content-Length bytes>
/// \r\n\r\n
/// ```
///
/// ## Why `BufRead` and not `Read`
///
/// `BufRead` wraps the underlying reader with an internal buffer (typically
/// 8 KB). Without it, each `read_line` or small read would trigger a syscall.
/// With `BufRead`, many small reads are served from the buffer, and syscalls
/// only happen when the buffer is exhausted. For sequential parsing of large
/// files, this amortization is critical — it's the difference between millions
/// of syscalls and thousands.
pub struct WarcRecordIter<R: BufRead> {
    reader: R,
    // Reused across records to avoid re-allocating for each header section.
    // `clear()` resets the length to 0 but keeps the allocated capacity.
    line_buf: String,
}

impl<R: BufRead> WarcRecordIter<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            line_buf: String::with_capacity(256),
        }
    }
}

impl<R: BufRead> Iterator for WarcRecordIter<R> {
    type Item = io::Result<WarcRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        // --- Phase 1: Find the start of the next WARC record ---
        //
        // WARC records start with "WARC/1.0\r\n". We skip blank lines
        // between records (the \r\n\r\n terminator of the previous record).
        loop {
            self.line_buf.clear();
            match self.reader.read_line(&mut self.line_buf) {
                Ok(0) => return None, // EOF
                Ok(_) => {
                    if self.line_buf.starts_with("WARC/") {
                        break; // Found record start
                    }
                    // Skip blank lines / record terminators between records
                }
                Err(e) => return Some(Err(e)),
            }
        }

        // --- Phase 2: Parse headers — only WARC-Type and Content-Length ---
        //
        // We read header lines until we hit the empty line (\r\n or \n)
        // that separates headers from body. For each line, we only check
        // if it starts with "WARC-Type:" or "Content-Length:". Everything
        // else is ignored — no allocation, no parsing.
        let mut is_response = false;
        let mut content_length: usize = 0;
        let mut target_uri = String::new();
        let mut date = String::new();

        loop {
            self.line_buf.clear();
            match self.reader.read_line(&mut self.line_buf) {
                Ok(0) => return None, // Unexpected EOF in headers
                Ok(_) => {
                    let trimmed = self.line_buf.trim();
                    if trimmed.is_empty() {
                        break; // End of headers (blank line)
                    }

                    // Case-insensitive prefix check for headers we care about.
                    // We compare against lowercase — WARC spec allows mixed case
                    // but Common Crawl consistently uses this capitalization.
                    if let Some(value) = trim_header(&self.line_buf, "WARC-Type:") {
                        is_response = value.eq_ignore_ascii_case("response");
                    } else if let Some(value) = trim_header(&self.line_buf, "Content-Length:") {
                        // Manual ASCII digit parsing — faster than str::parse::<usize>
                        // because we skip UTF-8 validation and error handling overhead.
                        // Content-Length is always a non-negative integer in ASCII digits.
                        content_length = parse_ascii_usize(value);
                    } else if let Some(value) = trim_header(&self.line_buf, "WARC-Target-URI:") {
                        target_uri = value.to_string();
                    } else if let Some(value) = trim_header(&self.line_buf, "WARC-Date:") {
                        date = value.to_string();
                    }
                }
                Err(e) => return Some(Err(e)),
            }
        }

        // --- Phase 3: Read or skip the body ---
        //
        // This is where the big optimization happens. For non-response records
        // (request, metadata, warcinfo, etc.), we skip the body entirely by
        // reading and discarding `content_length` bytes. The `warc` crate
        // reads and allocates the body for EVERY record, even ones we'll
        // immediately discard. Skipping saves ~60% of memory allocations
        // and data copying.
        if !is_response || content_length == 0 {
            // Skip body bytes by reading into a discard buffer.
            // We can't seek (gzip streams don't support seeking), so we
            // read and throw away the bytes. Using a stack buffer avoids
            // heap allocation for the skip operation.
            if let Err(e) = skip_bytes(&mut self.reader, content_length) {
                return Some(Err(e));
            }
            // Recurse to find the next response record.
            // This tail-recursive pattern is fine — Rust will optimize it,
            // and WARC files rarely have thousands of consecutive non-response
            // records (typically they alternate request/response).
            return self.next();
        }

        // Response record — read the body into a buffer.
        let mut body = vec![0u8; content_length];
        if let Err(e) = self.reader.read_exact(&mut body) {
            return Some(Err(e));
        }

        Some(Ok(WarcRecord { body, target_uri, date }))
    }
}

/// Extract the value portion of a WARC header line, if the line matches
/// the given header name (case-insensitive comparison).
///
/// Returns `None` if the line doesn't match the header name.
/// Returns `Some(value)` with the trimmed value after the colon.
fn trim_header<'a>(line: &'a str, header: &str) -> Option<&'a str> {
    // Case-insensitive prefix match: WARC spec allows mixed case headers,
    // though Common Crawl is consistent. Being defensive costs almost nothing.
    if line.len() >= header.len()
        && line[..header.len()].eq_ignore_ascii_case(header)
    {
        Some(line[header.len()..].trim())
    } else {
        None
    }
}

/// Parse an ASCII decimal string into a usize.
///
/// This is faster than `str::parse::<usize>()` because:
/// 1. No UTF-8 validation (we know it's ASCII from WARC headers)
/// 2. No error type construction (we return 0 for malformed input)
/// 3. No generic trait dispatch — just direct arithmetic
///
/// For Content-Length values (always non-negative integers), this is safe.
fn parse_ascii_usize(s: &str) -> usize {
    let mut result: usize = 0;
    for &b in s.as_bytes() {
        if b.is_ascii_digit() {
            result = result.wrapping_mul(10).wrapping_add((b - b'0') as usize);
        }
    }
    result
}

/// Skip `n` bytes from a reader by reading into a stack buffer and discarding.
///
/// We can't use `seek` because gzip decoders don't support it — the data
/// must be decompressed sequentially. So we read and discard using a 8 KB
/// stack buffer to avoid heap allocation for the skip operation.
fn skip_bytes<R: Read>(reader: &mut R, mut n: usize) -> io::Result<()> {
    let mut buf = [0u8; 8192];
    while n > 0 {
        let to_read = n.min(buf.len());
        let read = reader.read(&mut buf[..to_read])?;
        if read == 0 {
            break; // EOF — the record may have been truncated
        }
        n -= read;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Slice Parser — works on contiguous &[u8] (e.g., memory-mapped file)
// ---------------------------------------------------------------------------

/// A reference to a WARC response record within a memory-mapped slice.
///
/// Unlike `WarcRecord` which owns its data, this borrows directly
/// from the mmap. Zero allocation, zero copying — the bytes stay in
/// the OS page cache and are accessed through virtual memory.
pub struct WarcSlice<'a> {
    pub body: &'a [u8],
    pub target_uri: &'a [u8],
    pub date: &'a [u8],
}

/// Iterates WARC response records from a contiguous byte slice.
///
/// This parser uses `memchr::memmem` to find record and header boundaries
/// instead of line-by-line reading. On a contiguous slice, this is faster
/// because `memmem` uses SIMD to scan for the `\r\n\r\n` delimiter at
/// 16–32 bytes per CPU cycle.
///
/// Body references are zero-copy `&[u8]` slices into the original data.
pub struct WarcSliceIter<'a> {
    data: &'a [u8],
    pos: usize,
    // Pre-compiled searchers reused across all records.
    header_end_finder: memmem::Finder<'a>,
}

impl<'a> WarcSliceIter<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            header_end_finder: memmem::Finder::new(b"\r\n\r\n"),
        }
    }
}

impl<'a> Iterator for WarcSliceIter<'a> {
    type Item = WarcSlice<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Find the next "WARC/" magic in the remaining data.
            let remaining = &self.data[self.pos..];
            let warc_finder = memmem::Finder::new(b"WARC/");
            let warc_start = warc_finder.find(remaining)?;
            let record_start = self.pos + warc_start;

            // Find the end of the header section (\r\n\r\n).
            let after_magic = &self.data[record_start..];
            let header_end_offset = self.header_end_finder.find(after_magic)?;
            let body_start = record_start + header_end_offset + 4; // skip \r\n\r\n

            // Parse headers from the header section.
            let header_bytes = &self.data[record_start..record_start + header_end_offset];
            let mut is_response = false;
            let mut content_length: usize = 0;
            let mut target_uri: &[u8] = b"";
            let mut date: &[u8] = b"";

            // Split headers by \r\n and check each line.
            // We work on bytes to avoid UTF-8 conversion.
            for line in header_bytes.split(|&b| b == b'\n') {
                let line = strip_cr(line);
                if line.is_empty() {
                    continue;
                }
                if starts_with_ignore_case(line, b"warc-type:") {
                    let value = trim_bytes(&line[b"warc-type:".len()..]);
                    is_response = value.eq_ignore_ascii_case(b"response");
                } else if starts_with_ignore_case(line, b"content-length:") {
                    let value = trim_bytes(&line[b"content-length:".len()..]);
                    content_length = parse_ascii_usize_bytes(value);
                } else if starts_with_ignore_case(line, b"warc-target-uri:") {
                    target_uri = trim_bytes(&line[b"warc-target-uri:".len()..]);
                } else if starts_with_ignore_case(line, b"warc-date:") {
                    date = trim_bytes(&line[b"warc-date:".len()..]);
                }
            }

            // Advance past this record's body.
            let body_end = body_start + content_length;
            // Records are terminated by \r\n\r\n after the body.
            // Advance past the terminator (up to 4 bytes) for the next record.
            self.pos = (body_end + 4).min(self.data.len());

            if !is_response || content_length == 0 {
                continue; // Skip non-response records
            }

            if body_end > self.data.len() {
                return None; // Truncated record at end of file
            }

            // Zero-copy: the body and metadata are slices into the original mmap.
            return Some(WarcSlice {
                body: &self.data[body_start..body_end],
                target_uri,
                date,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Byte-level helper functions for the slice parser
// ---------------------------------------------------------------------------

/// Case-insensitive prefix check on byte slices.
fn starts_with_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len()
        && haystack[..needle.len()].eq_ignore_ascii_case(needle)
}

/// Trim leading/trailing ASCII whitespace from a byte slice.
fn trim_bytes(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|&b| !b.is_ascii_whitespace()).unwrap_or(s.len());
    let end = s.iter().rposition(|&b| !b.is_ascii_whitespace()).map_or(start, |p| p + 1);
    &s[start..end]
}

/// Strip a trailing \r from a byte slice (for \r\n line endings).
fn strip_cr(line: &[u8]) -> &[u8] {
    if line.last() == Some(&b'\r') {
        &line[..line.len() - 1]
    } else {
        line
    }
}

/// Parse ASCII digits from a byte slice into a usize.
fn parse_ascii_usize_bytes(s: &[u8]) -> usize {
    let mut result: usize = 0;
    for &b in s {
        if b.is_ascii_digit() {
            result = result.wrapping_mul(10).wrapping_add((b - b'0') as usize);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    /// Build a minimal WARC record as raw bytes with optional metadata.
    fn make_warc_record_with_meta(
        warc_type: &str,
        body: &[u8],
        target_uri: Option<&str>,
        date: Option<&str>,
    ) -> Vec<u8> {
        let mut record = Vec::new();
        record.extend_from_slice(b"WARC/1.0\r\n");
        record.extend_from_slice(format!("WARC-Type: {}\r\n", warc_type).as_bytes());
        record.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        if let Some(uri) = target_uri {
            record.extend_from_slice(format!("WARC-Target-URI: {}\r\n", uri).as_bytes());
        }
        if let Some(d) = date {
            record.extend_from_slice(format!("WARC-Date: {}\r\n", d).as_bytes());
        }
        record.extend_from_slice(b"\r\n");
        record.extend_from_slice(body);
        record.extend_from_slice(b"\r\n\r\n");
        record
    }

    /// Convenience wrapper for records without metadata.
    fn make_warc_record(warc_type: &str, body: &[u8]) -> Vec<u8> {
        make_warc_record_with_meta(warc_type, body, None, None)
    }

    /// Create a multi-record WARC byte stream with mixed record types.
    fn make_warc_stream() -> Vec<u8> {
        let mut stream = Vec::new();
        // A warcinfo record (should be skipped)
        stream.extend_from_slice(&make_warc_record("warcinfo", b"software: test"));
        // A request record (should be skipped)
        stream.extend_from_slice(&make_warc_record("request", b"GET / HTTP/1.1\r\nHost: example.com"));
        // A response record (should be returned) — with metadata
        stream.extend_from_slice(&make_warc_record_with_meta(
            "response",
            b"HTTP/1.1 200 OK\r\n\r\nHello world with abc2defghijklmnop.onion inside",
            Some("https://example.com/page1"),
            Some("2025-10-01T12:00:00Z"),
        ));
        // Another request (skipped)
        stream.extend_from_slice(&make_warc_record("request", b"GET /page HTTP/1.1"));
        // Another response (returned) — with metadata
        stream.extend_from_slice(&make_warc_record_with_meta(
            "response",
            b"HTTP/1.1 200 OK\r\n\r\nAnother page",
            Some("https://example.com/page2"),
            Some("2025-10-01T12:01:00Z"),
        ));
        stream
    }

    #[test]
    fn streaming_parser_only_returns_response_records() {
        let data = make_warc_stream();
        let reader = BufReader::new(data.as_slice());
        let records: Vec<_> = WarcRecordIter::new(reader)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(records.len(), 2, "Should return only the 2 response records");
        assert!(records[0].body.windows(6).any(|w| w == b".onion"),
            "First response should contain .onion");
        assert!(records[1].body.windows(7).any(|w| w == b"Another"),
            "Second response should contain 'Another'");
    }

    #[test]
    fn streaming_parser_extracts_metadata() {
        let data = make_warc_stream();
        let reader = BufReader::new(data.as_slice());
        let records: Vec<_> = WarcRecordIter::new(reader)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(records[0].target_uri, "https://example.com/page1");
        assert_eq!(records[0].date, "2025-10-01T12:00:00Z");
        assert_eq!(records[1].target_uri, "https://example.com/page2");
        assert_eq!(records[1].date, "2025-10-01T12:01:00Z");
    }

    #[test]
    fn slice_parser_only_returns_response_records() {
        let data = make_warc_stream();
        let records: Vec<_> = WarcSliceIter::new(&data).collect();

        assert_eq!(records.len(), 2, "Should return only the 2 response records");
        assert!(records[0].body.windows(6).any(|w| w == b".onion"),
            "First response should contain .onion");
    }

    #[test]
    fn slice_parser_extracts_metadata() {
        let data = make_warc_stream();
        let records: Vec<_> = WarcSliceIter::new(&data).collect();

        assert_eq!(records[0].target_uri, b"https://example.com/page1");
        assert_eq!(records[0].date, b"2025-10-01T12:00:00Z");
        assert_eq!(records[1].target_uri, b"https://example.com/page2");
        assert_eq!(records[1].date, b"2025-10-01T12:01:00Z");
    }

    #[test]
    fn both_parsers_produce_same_bodies() {
        let data = make_warc_stream();

        let streaming: Vec<Vec<u8>> = WarcRecordIter::new(BufReader::new(data.as_slice()))
            .map(|r| r.unwrap().body)
            .collect();

        let sliced: Vec<&[u8]> = WarcSliceIter::new(&data)
            .map(|s| s.body)
            .collect();

        assert_eq!(streaming.len(), sliced.len(), "Same number of records");
        for (s, sl) in streaming.iter().zip(sliced.iter()) {
            assert_eq!(s.as_slice(), *sl, "Bodies should be identical");
        }
    }

    #[test]
    fn empty_body_response_is_skipped() {
        let data = make_warc_record("response", b"");
        let reader = BufReader::new(data.as_slice());
        let records: Vec<_> = WarcRecordIter::new(reader)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(records.len(), 0, "Empty body responses are skipped");
    }

    #[test]
    fn parse_ascii_usize_works() {
        assert_eq!(parse_ascii_usize("12345"), 12345);
        assert_eq!(parse_ascii_usize("0"), 0);
        assert_eq!(parse_ascii_usize("  42  "), 42);
    }

    #[test]
    fn case_insensitive_warc_type() {
        // WARC spec allows mixed-case header names
        let mut record = Vec::new();
        record.extend_from_slice(b"WARC/1.0\r\n");
        record.extend_from_slice(b"warc-type: RESPONSE\r\n");
        record.extend_from_slice(b"content-length: 5\r\n");
        record.extend_from_slice(b"\r\n");
        record.extend_from_slice(b"hello");
        record.extend_from_slice(b"\r\n\r\n");

        // Streaming parser
        let reader = BufReader::new(record.as_slice());
        let records: Vec<_> = WarcRecordIter::new(reader)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].body, b"hello");

        // Slice parser
        let records: Vec<_> = WarcSliceIter::new(&record).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].body, b"hello");
    }
}
