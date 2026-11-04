// Custom byte-level WARC parser — ripgrep-inspired optimization
//
// The `warc` crate (v0.4) parses ALL headers with nom and allocates a HashMap
// per record. To find the pages we only need two pieces of information:
//   1. Is this record one of the pages? (WARC-Type header)
//   2. What are the body bytes? (Content-Length header + body data)
// and for a page, where and when it was crawled (WARC-Target-URI, WARC-Date)
// and the type Common Crawl detected from its bytes
// (WARC-Identified-Payload-Type).
//
// By parsing only these five headers and skipping the other records' bodies
// entirely, we avoid reading ~60% of the decompressed data into memory. This
// is the same philosophy ripgrep uses: do the minimum work to determine
// relevance, then only process what matters.
//
// Which `WARC-Type` holds the pages depends on the Format: `response` in
// WARC Archives, `conversion` in WET Archives (`Format::record_type`). The
// caller passes it to the iterator, which skips every other type.
//
// Two parser implementations:
//   - `WarcRecordIter<R: BufRead>` — streaming parser for sequential reads
//   - `WarcSliceIter<'a>` — slice parser for memory-mapped data (zero-copy)
//
// Both read records by the same rules, in functions they share, so every
// Transport reads an Archive alike, even one Common Crawl didn't write:
//   - lines are bytes, each ended by `\n`: a header line in any encoding is
//     read as it is, never failing the record;
//   - a record starts at the first line beginning `WARC/` after the end of
//     the previous body (`is_record_start`); lines before it are passed
//     over;
//   - its headers end at the first line of only ASCII whitespace, `\r\n`
//     or `\n` alike (`is_blank`);
//   - its header lines are read by `RecordHeaders`, its `Content-Length` by
//     `parse_content_length`: a record missing it, or with a malformed one,
//     fails the Archive.
// Both end where the data ends between two records, and fail with the same
// error where it ends inside one (`cut_record`), whatever its type.

use std::io::{self, BufRead, Read};

use memchr::memchr;

// ---------------------------------------------------------------------------
// Record rules shared by both parsers
// ---------------------------------------------------------------------------

/// Whether `line` starts a record: it begins `WARC/`, as `WARC/1.0` does.
fn is_record_start(line: &[u8]) -> bool {
    line.starts_with(b"WARC/")
}

/// Whether `line` ends a record's headers: it holds only ASCII whitespace,
/// such as `\r\n` or a bare `\n`.
fn is_blank(line: &[u8]) -> bool {
    line.iter().all(u8::is_ascii_whitespace)
}

/// What a record's headers say, as far as the parsers read them.
///
/// ## One reader of header lines, two ways to keep a value
///
/// Both parsers hand each header line to `read`, so a line means the same
/// on every Transport. They keep a value in different ways: the streaming
/// parser reads the next line into the same buffer, so it copies a value
/// into a `Vec<u8>` of its own; the slice parser keeps a `&[u8]` into the
/// data, which outlives every line. `V` is that type, and `read` builds it
/// with `V::from`: `Vec::from(&[u8])` copies the bytes, and every type
/// converts from itself (`impl<T> From<T> for T`), so a `&[u8]` stays the
/// slice it is.
///
/// `#[derive(Default)]` writes a `default()` for any `V` that has one
/// itself: `false`, `None`, and two empty values, `Vec::new()` or `&[]`.
#[derive(Default)]
struct RecordHeaders<V> {
    /// Whether the record's `WARC-Type` is the one the parser returns.
    is_wanted: bool,
    /// Its `Content-Length`, as `parse_content_length` read it; `None` if
    /// it has none.
    content_length: Option<io::Result<usize>>,
    /// Its `WARC-Target-URI`: the page's URL. Empty if it has none.
    target_uri: V,
    /// Its `WARC-Date`: when the record was written. Empty if it has none.
    date: V,
    /// Its `WARC-Identified-Payload-Type`: the type Common Crawl detected
    /// from the payload's bytes. Empty if it has none.
    identified_payload_type: V,
}

impl<V> RecordHeaders<V> {
    /// Read one header `line`, keeping what it says if it is a header the
    /// parsers read: `WARC-Type` (compared with `record_type`),
    /// `Content-Length`, `WARC-Target-URI`, `WARC-Date` or
    /// `WARC-Identified-Payload-Type`. Any other line is passed over. A
    /// header given twice keeps its last value.
    ///
    /// The bound `V: From<&'a [u8]>` sits on the method, where `'a` is
    /// known: for a `&[u8]`, it must be the data's lifetime, so that a value
    /// kept outlives the line; a `Vec<u8>` converts from a slice of any.
    fn read<'a>(&mut self, line: &'a [u8], record_type: &str)
    where
        V: From<&'a [u8]>,
    {
        if let Some(value) = header_value(line, b"WARC-Type:") {
            self.is_wanted = value.eq_ignore_ascii_case(record_type.as_bytes());
        } else if let Some(value) = header_value(line, b"Content-Length:") {
            self.content_length = Some(parse_content_length(value));
        } else if let Some(value) = header_value(line, b"WARC-Target-URI:") {
            self.target_uri = V::from(value);
        } else if let Some(value) = header_value(line, b"WARC-Date:") {
            self.date = V::from(value);
        } else if let Some(value) = header_value(line, b"WARC-Identified-Payload-Type:") {
            self.identified_payload_type = V::from(value);
        }
    }

    /// The body length the headers declare, or the error of a record whose
    /// `Content-Length` is malformed or missing: without its length, a body
    /// can't be told from the records after it.
    ///
    /// `Option::take` moves the value out, leaving `None` behind: an
    /// `io::Error` can't be copied, so it is moved out of `self` to be
    /// returned.
    fn body_length(&mut self) -> io::Result<usize> {
        self.content_length.take().unwrap_or_else(|| {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "a record has no Content-Length",
            ))
        })
    }
}

/// The value of `line` if it is the header `name` (`WARC-Type:`, ...),
/// without the ASCII whitespace around it. `name` is compared ignoring
/// ASCII case: WARC allows names in any case, though Common Crawl writes
/// them as above. HTTP header lines are read alike (`charset` reads the
/// `Content-Type:`), hence `pub(crate)`.
///
/// `split_at_checked` cuts `line` after `name.len()` bytes, or returns
/// `None` if it is shorter. A cut in bytes is always possible, where
/// slicing a `str` panics if the cut falls inside a multi-byte character.
pub(crate) fn header_value<'a>(line: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let (head, value) = line.split_at_checked(name.len())?;
    head.eq_ignore_ascii_case(name).then(|| value.trim_ascii())
}

/// The body length a `Content-Length` header's `value` gives, the
/// whitespace around it removed: ASCII digits. Anything else fails,
/// whatever the record's type: a sign, any other byte, no digit at all, or
/// a number too large for a `usize`.
///
/// ## Overflow: `checked_*` arithmetic
///
/// `usize` arithmetic that overflows panics in a debug build and wraps
/// around in a release one: `99999999999999999999999` would read as some
/// smaller number. `checked_mul` and `checked_add` return `None` instead.
/// `try_fold` folds the digits into a number as `fold` does, but stops at
/// the first `None` the closure returns; inside the closure, `?` on an
/// `Option` returns that `None`.
fn parse_content_length(value: &[u8]) -> io::Result<usize> {
    let length = if value.is_empty() {
        None
    } else {
        value.iter().try_fold(0usize, |length, &byte| {
            if !byte.is_ascii_digit() {
                return None;
            }
            length
                .checked_mul(10)?
                .checked_add(usize::from(byte - b'0'))
        })
    };
    // `escape_ascii` shows the bytes as text: printable ASCII as it is,
    // anything else escaped (`\xff`, `\"`, ...).
    length.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "a record's Content-Length is not a byte count: \"{}\"",
                value.escape_ascii()
            ),
        )
    })
}

/// The error of data ending inside a record: in its headers, or before the
/// end of its body, read or passed over.
///
/// ## The end of the data: normal end or error
///
/// A reader returning `Ok(0)` only says the data ended, not whether it
/// could end there. Between records it can: that is the end of the
/// Archive. Inside one it can't: the gzip stream ended cleanly, but the
/// last record is cut. Reading that as the end would drop the rest of the
/// Archive without a word, and mark its pair done.
///
/// The kind is `UnexpectedEof`, as `read_exact` gives; the message says
/// what was cut, where `read_exact`'s says only `failed to fill whole
/// buffer`. Both parsers return this error, so every Transport fails with
/// the same message.
fn cut_record() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "the Archive ends inside a record",
    )
}

// ---------------------------------------------------------------------------
// Streaming Parser — works with BufRead (e.g., gzip decoder + BufReader)
// ---------------------------------------------------------------------------

/// The most memory the streaming parser reserves for a body before reading
/// it: a body declared larger starts there, and grows only with the bytes
/// that arrive. A little above any real record: Common Crawl cuts each page
/// it fetches at 1 MiB (reportedly 5 MiB in crawls since 2025), so the
/// largest records fit at once, and a malformed `Content-Length` can't
/// reserve more.
const MAX_BODY_RESERVE: usize = 8 * 1024 * 1024;

/// A parsed WARC record of the wanted type — the fields we need for .onion
/// extraction.
///
/// Records of other types are skipped entirely (their bodies are never
/// read). This struct only exists for records whose `WARC-Type` is the one
/// the iterator was built with.
///
/// In addition to the body, we extract metadata from WARC headers:
/// - `target_uri`: the original URL that was crawled (WARC-Target-URI header)
/// - `date`: the timestamp of the crawl (WARC-Date header)
/// - `identified_payload_type`: the type Common Crawl detected from the
///   payload's bytes, such as `text/html` (WARC-Identified-Payload-Type
///   header, written in CC-MAIN, not in CC-NEWS)
///
/// The first two let us track *where* and *when* each .onion address was
/// found, not just *which archive* it appeared in. They are the header's
/// bytes, as `WarcSlice`'s, empty when the record has none: the caller
/// reads them as text.
pub struct WarcRecord {
    pub body: Vec<u8>,
    pub target_uri: Vec<u8>,
    pub date: Vec<u8>,
    pub identified_payload_type: Vec<u8>,
}

/// Iterates the WARC records of one type from a `BufRead` source.
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
/// 8 KB). Without it, each `read_until` or small read would trigger a
/// syscall. With `BufRead`, many small reads are served from the buffer, and
/// syscalls only happen when the buffer is exhausted. For sequential parsing
/// of large files, this amortization is critical — it's the difference
/// between millions of syscalls and thousands.
pub struct WarcRecordIter<R: BufRead> {
    reader: R,
    // The `WARC-Type` of the records returned; all others are skipped.
    record_type: &'static str,
    // Reused across records to avoid re-allocating for each header section.
    // `clear()` resets the length to 0 but keeps the allocated capacity.
    line_buf: Vec<u8>,
}

impl<R: BufRead> WarcRecordIter<R> {
    /// Iterate the records of `reader` whose `WARC-Type` is `record_type`
    /// (`response`, `conversion`, ...).
    pub fn new(reader: R, record_type: &'static str) -> Self {
        Self {
            reader,
            record_type,
            line_buf: Vec::with_capacity(256),
        }
    }

    /// Read the next line into `line_buf`, its `\n` included: the rest of
    /// the data if no `\n` is left, nothing at the end of the data.
    ///
    /// `read_until` reads bytes, where `read_line` would fail on a line
    /// that isn't UTF-8: a header line in another encoding is read as it
    /// is, as the slice parser reads it.
    fn read_line(&mut self) -> io::Result<usize> {
        self.line_buf.clear();
        self.reader.read_until(b'\n', &mut self.line_buf)
    }
}

impl<R: BufRead> Iterator for WarcRecordIter<R> {
    type Item = io::Result<WarcRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        // Each pass of this outer loop parses one record. Skipped records
        // `continue` to the next pass instead of calling `self.next()`
        // recursively: Rust does not guarantee tail-call elimination, so
        // recursion would cost one stack frame per skipped record.
        loop {
            // --- Phase 1: Find the start of the next WARC record ---
            //
            // The first line beginning `WARC/`. Lines before it are passed
            // over: the blank lines ending the previous record, or anything
            // else.
            loop {
                match self.read_line() {
                    Ok(0) => return None, // EOF between records: the end
                    Ok(_) if is_record_start(&self.line_buf) => break,
                    Ok(_) => {}
                    Err(e) => return Some(Err(e)),
                }
            }

            // --- Phase 2: Parse headers ---
            //
            // We read header lines until the blank line that separates
            // headers from body. Each line goes to `RecordHeaders::read`,
            // which keeps only the four headers we need.
            let mut headers = RecordHeaders::<Vec<u8>>::default();
            loop {
                match self.read_line() {
                    // The data ends between `WARC/` and the blank line.
                    Ok(0) => return Some(Err(cut_record())),
                    // `read_until` returns a line without its `\n` only at
                    // the end of the data: it ends inside this line, even a
                    // blank one cut after its `\r`.
                    Ok(_) if !self.line_buf.ends_with(b"\n") => {
                        return Some(Err(cut_record()));
                    }
                    Ok(_) if is_blank(&self.line_buf) => break, // End of headers
                    Ok(_) => headers.read(&self.line_buf, self.record_type),
                    Err(e) => return Some(Err(e)),
                }
            }

            // --- Phase 3: Read or skip the body ---
            //
            // This is where the big optimization happens. For records of other
            // types (request, metadata, warcinfo, etc. in a WARC Archive), we
            // skip the body entirely by reading and discarding `content_length`
            // bytes. The `warc` crate reads and allocates the body for EVERY
            // record, even ones we'll immediately discard. Skipping saves ~60%
            // of memory allocations and data copying.
            let content_length = match headers.body_length() {
                Ok(length) => length,
                Err(e) => return Some(Err(e)),
            };
            if !headers.is_wanted || content_length == 0 {
                // Skip body bytes by reading into a discard buffer.
                // We can't seek (gzip streams don't support seeking), so we
                // read and throw away the bytes. Using a stack buffer avoids
                // heap allocation for the skip operation.
                if let Err(e) = skip_bytes(&mut self.reader, content_length) {
                    return Some(Err(e));
                }
                continue; // Move on to the next record
            }

            // Wanted record — read the body into a buffer that grows with
            // the bytes that arrive, never reserved at more than
            // `MAX_BODY_RESERVE` up front. A `vec![0u8; content_length]`
            // would trust the header: a length past `isize::MAX` panics
            // (capacity overflow), and one the machine can't hold aborts
            // the process, every Shard in flight with it.
            //
            // `by_ref` lends the reader to `take` instead of moving it in;
            // `take` reads at most `content_length` bytes from it, then
            // ends as the data would; `read_to_end` appends what it reads
            // until that end, growing the `Vec` as needed, and retries a
            // read `Interrupted` by a signal. Fewer bytes than declared:
            // the data ended inside the body. A gzip error passes up as it
            // is. (`as u64` is lossless: a `usize` has at most 64 bits.)
            let mut body = Vec::with_capacity(content_length.min(MAX_BODY_RESERVE));
            match self
                .reader
                .by_ref()
                .take(content_length as u64)
                .read_to_end(&mut body)
            {
                Ok(read) if read < content_length => return Some(Err(cut_record())),
                Ok(_) => {}
                Err(e) => return Some(Err(e)),
            }

            return Some(Ok(WarcRecord {
                body,
                target_uri: headers.target_uri,
                date: headers.date,
                identified_payload_type: headers.identified_payload_type,
            }));
        }
    }
}

/// Fill `buf` from `reader`, failing with `cut_record` if the data ends
/// first.
///
/// Like `read_exact`, which retries a read `Interrupted` by a signal. Not
/// `read_exact` itself: its `UnexpectedEof` can't be told apart from the
/// gzip decoder's own (a gzip member cut short), which comes out of `read`
/// as an error and must pass up as it is.
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => return Err(cut_record()),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Skip `n` bytes from a reader by reading into a stack buffer and discarding.
///
/// We can't use `seek` because gzip decoders don't support it — the data
/// must be decompressed sequentially. So we read and discard using a 8 KB
/// stack buffer to avoid heap allocation for the skip operation. A body
/// passed over must be complete too: data ending inside it fails.
fn skip_bytes<R: Read>(reader: &mut R, mut n: usize) -> io::Result<()> {
    let mut buf = [0u8; 8192];
    while n > 0 {
        let to_read = n.min(buf.len());
        read_full(reader, &mut buf[..to_read])?;
        n -= to_read;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Slice Parser — works on contiguous &[u8] (e.g., memory-mapped file)
// ---------------------------------------------------------------------------

/// A reference to a WARC record of the wanted type within a memory-mapped
/// slice.
///
/// Unlike `WarcRecord` which owns its data, this borrows directly
/// from the mmap. Zero allocation, zero copying — the bytes stay in
/// the OS page cache and are accessed through virtual memory.
pub struct WarcSlice<'a> {
    pub body: &'a [u8],
    pub target_uri: &'a [u8],
    pub date: &'a [u8],
    pub identified_payload_type: &'a [u8],
}

/// Iterates the WARC records of one type from a contiguous byte slice.
///
/// This parser reads the data line by line as the streaming one does, but
/// finds each line's end with `memchr`, which scans for the `\n` with SIMD
/// instructions, 16 to 32 bytes at a time, and copies nothing: a line is a
/// slice of the data.
///
/// Body references are zero-copy `&[u8]` slices into the original data.
///
/// ## An iterator whose items can fail
///
/// The data can end inside a record, and that is an error, not the end of
/// the records. `Option<WarcSlice>` can only say "here is one" or "there
/// are no more", so each item is an `io::Result`, as `WarcRecordIter`'s:
/// `None` still means the records ended where they may, `Some(Err(..))`
/// that they didn't. A caller collecting into `Result<Vec<_>, _>` stops at
/// the first error; one using `?` in a `for` loop returns it. The iterator
/// itself returns `None` after its error, so a caller that ignores it
/// doesn't loop forever.
pub struct WarcSliceIter<'a> {
    data: &'a [u8],
    pos: usize,
    // The `WARC-Type` of the records returned; all others are skipped.
    record_type: &'static str,
}

impl<'a> WarcSliceIter<'a> {
    /// Iterate the records of `data` whose `WARC-Type` is `record_type`
    /// (`response`, `conversion`, ...).
    pub fn new(data: &'a [u8], record_type: &'static str) -> Self {
        Self {
            data,
            pos: 0,
            record_type,
        }
    }

    /// The next line of the data, its `\n` included: the rest of the data
    /// if no `\n` is left, `None` at the end of the data. Moves past it.
    ///
    /// `self.data` is copied out first: slicing that `&'a [u8]` gives a
    /// line that lives as long as the data, not only as long as this
    /// borrow of `self`.
    fn next_line(&mut self) -> Option<&'a [u8]> {
        let data = self.data;
        let rest = &data[self.pos..];
        if rest.is_empty() {
            return None;
        }
        let len = memchr(b'\n', rest).map_or(rest.len(), |newline| newline + 1);
        self.pos += len;
        Some(&rest[..len])
    }

    /// Return `error`, and end the iteration there, so the next call
    /// returns `None`.
    fn fail(&mut self, error: io::Error) -> Option<io::Result<WarcSlice<'a>>> {
        self.pos = self.data.len();
        Some(Err(error))
    }

    /// The data ends inside a record: fail with `cut_record`.
    fn end_inside_record(&mut self) -> Option<io::Result<WarcSlice<'a>>> {
        self.fail(cut_record())
    }
}

impl<'a> Iterator for WarcSliceIter<'a> {
    type Item = io::Result<WarcSlice<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Find the next line beginning `WARC/`. None left: the records
            // ended between two of them, the normal end.
            loop {
                let line = self.next_line()?;
                if is_record_start(line) {
                    break;
                }
            }

            // Read the header lines up to the blank line. A line without
            // its `\n` is the end of the data: it ends inside the headers.
            let mut headers = RecordHeaders::<&[u8]>::default();
            loop {
                match self.next_line() {
                    Some(line) if line.ends_with(b"\n") => {
                        if is_blank(line) {
                            break;
                        }
                        headers.read(line, self.record_type);
                    }
                    _ => return self.end_inside_record(),
                }
            }

            let content_length = match headers.body_length() {
                Ok(length) => length,
                Err(e) => return self.fail(e),
            };
            // The data ends inside the body, whether it is read or passed
            // over. Compared as a length left, as `body_start +
            // content_length` could overflow on a huge Content-Length.
            let body_start = self.pos;
            if content_length > self.data.len() - body_start {
                return self.end_inside_record();
            }

            // The next record is looked for from the end of this body,
            // whatever follows it.
            let body_end = body_start + content_length;
            self.pos = body_end;

            if !headers.is_wanted || content_length == 0 {
                continue; // Skip records of other types
            }

            // Zero-copy: the body and metadata are slices into the original mmap.
            return Some(Ok(WarcSlice {
                body: &self.data[body_start..body_end],
                target_uri: headers.target_uri,
                date: headers.date,
                identified_payload_type: headers.identified_payload_type,
            }));
        }
    }
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
        stream.extend_from_slice(&make_warc_record(
            "request",
            b"GET / HTTP/1.1\r\nHost: example.com",
        ));
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
        let records: Vec<_> = WarcRecordIter::new(reader, "response")
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(
            records.len(),
            2,
            "Should return only the 2 response records"
        );
        assert!(
            records[0].body.windows(6).any(|w| w == b".onion"),
            "First response should contain .onion"
        );
        assert!(
            records[1].body.windows(7).any(|w| w == b"Another"),
            "Second response should contain 'Another'"
        );
    }

    #[test]
    fn streaming_parser_extracts_metadata() {
        let data = make_warc_stream();
        let reader = BufReader::new(data.as_slice());
        let records: Vec<_> = WarcRecordIter::new(reader, "response")
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(records[0].target_uri, b"https://example.com/page1");
        assert_eq!(records[0].date, b"2025-10-01T12:00:00Z");
        assert_eq!(records[1].target_uri, b"https://example.com/page2");
        assert_eq!(records[1].date, b"2025-10-01T12:01:00Z");
    }

    #[test]
    fn slice_parser_only_returns_response_records() {
        let data = make_warc_stream();
        let records: Vec<_> = WarcSliceIter::new(&data, "response")
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(
            records.len(),
            2,
            "Should return only the 2 response records"
        );
        assert!(
            records[0].body.windows(6).any(|w| w == b".onion"),
            "First response should contain .onion"
        );
    }

    #[test]
    fn slice_parser_extracts_metadata() {
        let data = make_warc_stream();
        let records: Vec<_> = WarcSliceIter::new(&data, "response")
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(records[0].target_uri, b"https://example.com/page1");
        assert_eq!(records[0].date, b"2025-10-01T12:00:00Z");
        assert_eq!(records[1].target_uri, b"https://example.com/page2");
        assert_eq!(records[1].date, b"2025-10-01T12:01:00Z");
    }

    #[test]
    fn both_parsers_produce_same_bodies() {
        let data = make_warc_stream();

        let streaming: Vec<Vec<u8>> =
            WarcRecordIter::new(BufReader::new(data.as_slice()), "response")
                .map(|r| r.unwrap().body)
                .collect();

        let sliced: Vec<&[u8]> = WarcSliceIter::new(&data, "response")
            .map(|s| s.unwrap().body)
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
        let records: Vec<_> = WarcRecordIter::new(reader, "response")
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(records.len(), 0, "Empty body responses are skipped");
    }

    #[test]
    fn streaming_parser_survives_long_run_of_skipped_records() {
        // WAT Archives contain tens of thousands of consecutive `metadata`
        // records. Skipping them must not grow the stack per record.
        let mut data = make_warc_record("metadata", b"{}").repeat(100_000);
        data.extend_from_slice(&make_warc_record("response", b"hello"));

        let reader = BufReader::new(data.as_slice());
        let records: Vec<_> = WarcRecordIter::new(reader, "response")
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(records.len(), 1, "Only the trailing response is returned");
        assert_eq!(records[0].body, b"hello");
    }

    /// What each parser, streaming then slice, reads from a `response`
    /// record with `hello` for body and `Content-Length:<value>` among its
    /// headers: the body, or the error's message.
    fn read_with_content_length(value: &str) -> [Result<Vec<u8>, String>; 2] {
        let record = format!(
            "WARC/1.0\r\nWARC-Type: response\r\nContent-Length:{value}\r\n\r\nhello\r\n\r\n"
        );
        let data = record.as_bytes();
        let streaming = WarcRecordIter::new(BufReader::new(data), "response")
            .next()
            .unwrap()
            .map(|record| record.body);
        let sliced = WarcSliceIter::new(data, "response")
            .next()
            .unwrap()
            .map(|record| record.body.to_vec());
        [streaming, sliced].map(|result| result.map_err(|e| e.to_string()))
    }

    #[test]
    fn content_length_is_ascii_digits_with_whitespace_around() {
        for value in ["5", " 5", "5 ", "\t5\t", " 005"] {
            let hello = Ok(b"hello".to_vec());
            assert_eq!(
                read_with_content_length(value),
                [hello.clone(), hello],
                "{value:?}"
            );
        }
        // `٥` is the Arabic-Indic digit five: a digit, but not ASCII.
        for value in [" +5", " 5 5", " 0x5", " 5.0", " ٥"] {
            let [streaming, sliced] = read_with_content_length(value);
            let message = streaming.expect_err(value);
            assert!(
                message.starts_with("a record's Content-Length is not a byte count: "),
                "{value:?}: {message}"
            );
            assert_eq!(sliced, Err(message), "{value:?}");
        }
    }

    #[test]
    fn the_last_content_length_wins() {
        // Each value below holds a line break: a second `Content-Length`
        // header follows the first.
        let hello = Ok(b"hello".to_vec());
        assert_eq!(
            read_with_content_length(" 12a3\r\nContent-Length: 5"),
            [hello.clone(), hello]
        );
        let message = r#"a record's Content-Length is not a byte count: "x""#.to_string();
        assert_eq!(
            read_with_content_length(" 5\r\nContent-Length: x"),
            [Err(message.clone()), Err(message)]
        );
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
        let records: Vec<_> = WarcRecordIter::new(reader, "response")
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].body, b"hello");

        // Slice parser
        let records: Vec<_> = WarcSliceIter::new(&record, "response")
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].body, b"hello");
    }
}
