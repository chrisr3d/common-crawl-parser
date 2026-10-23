// Page records — one crawled page, as every extractor sees it
//
// The record parsers in `warc_parser` produce different types: the streaming
// parser owns its bytes (`WarcRecord`), the mmap parser borrows them from
// the mapped file (`WarcSlice`). `parse_archive` turns either into a
// `PageRecord` that *borrows* the same bytes, so extractors work on one
// type without anything being copied.
//
// One variant per Format. Only WARC is read today; WAT and WET get their
// own variants when their parsers arrive.

use memchr::memmem;

/// One crawled page read from an Archive.
///
/// ## Lifetimes: `PageRecord<'a>`
///
/// A `PageRecord` holds references (`&'a str`, `&'a [u8]`), not owned data.
/// The lifetime parameter `'a` names how long the borrowed bytes live, and
/// the compiler checks that no `PageRecord` outlives them. In the parsing
/// loop, `'a` is one iteration: the record borrows the current
/// `WarcRecord`'s buffers (or a region of the mmap) and is gone before the
/// next record is read.
///
/// ## Matching on a one-variant enum
///
/// Extractors `match` on the record even though there is a single variant
/// today. When a `Wat` variant is added, every such `match` stops compiling
/// until it says what to do with WAT records, so no extractor can silently
/// ignore a new Format.
pub enum PageRecord<'a> {
    /// A WARC `response` record.
    Warc(WarcResponse<'a>),
}

impl<'a> PageRecord<'a> {
    /// URL of the crawled page.
    pub fn page_url(&self) -> &'a str {
        match self {
            PageRecord::Warc(response) => response.page_url,
        }
    }

    /// When the page was crawled.
    pub fn date(&self) -> &'a str {
        match self {
            PageRecord::Warc(response) => response.date,
        }
    }
}

/// A WARC `response` record: page URL, crawl date and the full HTTP response.
pub struct WarcResponse<'a> {
    /// The `WARC-Target-URI` header.
    pub page_url: &'a str,
    /// The `WARC-Date` header.
    pub date: &'a str,
    /// The complete HTTP response: status line, headers, blank line, body.
    pub http_response: &'a [u8],
}

impl<'a> WarcResponse<'a> {
    /// The HTTP body, if the response declares an HTML `Content-Type`.
    ///
    /// `None` for other content types and for malformed responses with no
    /// blank line between headers and body.
    pub fn html_body(&self) -> Option<&'a [u8]> {
        let (http_headers, http_body) = split_http_response(self.http_response)?;
        is_html_content(http_headers).then_some(http_body)
    }
}

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
        if trimmed.len() > 13 && trimmed[..13].eq_ignore_ascii_case(b"content-type:") {
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

