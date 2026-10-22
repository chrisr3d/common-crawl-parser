// Shared helpers for the integration tests in `tests/`.
//
// ## Why `tests/common/mod.rs` and not `tests/common.rs`
//
// Cargo compiles every `.rs` file directly inside `tests/` as its own test
// crate. A `tests/common.rs` would become an extra test binary with zero
// tests in it. Files in subdirectories are not compiled on their own, so
// `tests/common/mod.rs` is only built when a test file pulls it in with
// `mod common;`.
//
// Integration tests see the crate exactly like an outside user does: only
// `pub` items, imported by crate name (`onion_crawler::...`).

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::Debug;
// Two traits named `Write`: `io::Write` lets `write!` target a `Vec<u8>`,
// `fmt::Write` lets it target a `String`. `as _` imports the second one's
// methods without binding its name, so the two don't clash.
use std::fmt::Write as _;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use flate2::Compression;
use flate2::write::GzEncoder;
use onion_crawler::{
    FaviconSource, OnionSource, ParseResult, parse_warc, parse_warc_bytes,
    parse_warc_bytes_from_memory, parse_warc_memchr, parse_warc_memchr_from_memory,
    parse_warc_mmap,
};
use regex::Regex;

// ---------------------------------------------------------------------------
// Building WARC Archives
// ---------------------------------------------------------------------------

/// Builds a gzipped WARC Archive in memory, one record at a time.
///
/// Common Crawl compresses every record as its own gzip member and
/// concatenates the members into one `.warc.gz` file. A plain `GzDecoder`
/// stops after the first member; the parsers must use `MultiGzDecoder` (and
/// the `warc` crate libflate's `MultiDecoder`) to see every record. Building
/// the fixture the same way means a reader that forgets this only sees the
/// first record, and the tests catch it.
///
/// The methods take `self` by value and return it (a *consuming builder*),
/// so a whole Archive reads as one chain of calls:
///
/// ```text
/// WarcBuilder::new().warcinfo(..).request(..).response(..).finish()
/// ```
pub struct WarcBuilder {
    archive: Vec<u8>,
    records_written: u32,
}

impl WarcBuilder {
    pub fn new() -> Self {
        Self {
            archive: Vec::new(),
            records_written: 0,
        }
    }

    /// Append one record, compressed as its own gzip member.
    ///
    /// `Content-Length` is computed from `block`, and every record gets a
    /// unique `WARC-Record-ID`: the `warc` crate (baseline parser) rejects
    /// records without one.
    fn record(
        mut self,
        warc_type: &str,
        target_uri: Option<&str>,
        date: &str,
        content_type: &str,
        block: &[u8],
    ) -> Self {
        self.records_written += 1;

        // `Vec<u8>` implements `io::Write`, so `write!` formats straight into
        // the byte buffer. Writing to a `Vec` cannot fail, hence `unwrap`.
        let mut record = Vec::new();
        write!(record, "WARC/1.0\r\n").unwrap();
        write!(record, "WARC-Type: {warc_type}\r\n").unwrap();
        write!(record, "WARC-Date: {date}\r\n").unwrap();
        write!(
            record,
            "WARC-Record-ID: <urn:uuid:00000000-0000-0000-0000-{:012}>\r\n",
            self.records_written
        )
        .unwrap();
        write!(record, "Content-Length: {}\r\n", block.len()).unwrap();
        write!(record, "Content-Type: {content_type}\r\n").unwrap();
        if let Some(uri) = target_uri {
            write!(record, "WARC-Target-URI: {uri}\r\n").unwrap();
        }
        record.extend_from_slice(b"\r\n");
        record.extend_from_slice(block);
        record.extend_from_slice(b"\r\n\r\n");

        let mut member = GzEncoder::new(Vec::new(), Compression::default());
        member.write_all(&record).unwrap();
        self.archive.extend(member.finish().unwrap());
        self
    }

    /// A `warcinfo` record: describes the Archive itself, has no target URI.
    pub fn warcinfo(self, date: &str, fields: &str) -> Self {
        self.record(
            "warcinfo",
            None,
            date,
            "application/warc-fields",
            fields.as_bytes(),
        )
    }

    /// A `request` record: the HTTP request the crawler sent.
    pub fn request(self, target_uri: &str, date: &str, http_request: &str) -> Self {
        self.record(
            "request",
            Some(target_uri),
            date,
            "application/http; msgtype=request",
            http_request.as_bytes(),
        )
    }

    /// A `response` record: the full HTTP response, headers and body.
    pub fn response(self, target_uri: &str, date: &str, http_response: &[u8]) -> Self {
        self.record(
            "response",
            Some(target_uri),
            date,
            "application/http; msgtype=response",
            http_response,
        )
    }

    /// A `metadata` record: crawler notes about the fetch.
    pub fn metadata(self, target_uri: &str, date: &str, fields: &str) -> Self {
        self.record(
            "metadata",
            Some(target_uri),
            date,
            "application/warc-fields",
            fields.as_bytes(),
        )
    }

    /// The finished `.warc.gz` bytes.
    pub fn finish(self) -> Vec<u8> {
        self.archive
    }
}

/// Build an HTTP `200 OK` response: status line, `headers`, blank line, `body`.
pub fn http_response(headers: &[(&str, &str)], body: &str) -> Vec<u8> {
    let mut response = Vec::new();
    write!(response, "HTTP/1.1 200 OK\r\n").unwrap();
    for (name, value) in headers {
        write!(response, "{name}: {value}\r\n").unwrap();
    }
    write!(response, "\r\n{body}").unwrap();
    response
}

/// Write `bytes` to `<tmp>/<test_name>/<file_name>` and return the path.
///
/// `CARGO_TARGET_TMPDIR` is set by Cargo only when compiling integration
/// tests and benchmarks: a scratch directory inside `target/`. `env!` reads
/// it at compile time. Tests run in parallel threads, so each test gets its
/// own subdirectory; the `mmap` strategy also writes a decompressed `.warc`
/// next to the Archive, which must not collide either.
pub fn write_archive(test_name: &str, file_name: &str, bytes: &[u8]) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(test_name);
    // Start clean: a previous aborted run may have left files behind.
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(file_name);
    fs::write(&path, bytes).unwrap();
    path
}

// ---------------------------------------------------------------------------
// Comparing parse results
// ---------------------------------------------------------------------------

/// One page an Artifact was seen on.
///
/// The crate's `OnionSource` and `FaviconSource` don't implement `PartialEq`,
/// and issue 03 replaces both with a single type. Converting both to this
/// local type keeps the pinned expectations independent of that change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sighting {
    pub page_url: String,
    pub date: String,
    pub archive: String,
}

impl Sighting {
    pub fn new(page_url: &str, date: &str, archive: &str) -> Self {
        Self {
            page_url: page_url.to_string(),
            date: date.to_string(),
            archive: archive.to_string(),
        }
    }
}

impl From<OnionSource> for Sighting {
    fn from(source: OnionSource) -> Self {
        Self {
            page_url: source.url,
            date: source.date,
            archive: source.archive,
        }
    }
}

impl From<FaviconSource> for Sighting {
    fn from(source: FaviconSource) -> Self {
        Self {
            page_url: source.page_url,
            date: source.date,
            archive: source.archive,
        }
    }
}

/// Convert a list of library sources, keeping their order.
///
/// Generic over any `T` that converts into a `Sighting`, so the same
/// function serves both `OnionSource` and `FaviconSource`.
fn sightings<T: Into<Sighting>>(sources: Vec<T>) -> Vec<Sighting> {
    sources.into_iter().map(Into::into).collect()
}

/// A `ParseResult` in a form that can be compared with `==` and printed.
///
/// `BTreeMap` instead of `HashMap`: same equality, but `Debug` prints keys in
/// sorted order, so two failing runs print the same diff.
///
/// Inline favicons are keyed by their decoded bytes, not by the crate's
/// hash key: that key comes from `DefaultHasher`, whose algorithm the
/// standard library may change between Rust releases.
#[derive(Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub onions: BTreeMap<String, Vec<Sighting>>,
    pub favicon_urls: BTreeMap<String, Vec<Sighting>>,
    pub inline_favicons: BTreeMap<Vec<u8>, Vec<Sighting>>,
}

impl From<ParseResult> for Snapshot {
    fn from(result: ParseResult) -> Self {
        Self {
            onions: result
                .onions
                .into_iter()
                .map(|(onion, sources)| (onion, sightings(sources)))
                .collect(),
            favicon_urls: result
                .favicon_urls
                .into_iter()
                .map(|(url, sources)| (url, sightings(sources)))
                .collect(),
            inline_favicons: result
                .inline_favicons
                .into_values()
                .map(|(bytes, sources)| (bytes, sightings(sources)))
                .collect(),
        }
    }
}

/// The onion pattern `main.rs` compiles and passes to the baseline `parse_warc`.
const ONION_PATTERN: &str = r"\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b";

type ParseOutcome = Result<ParseResult, Box<dyn Error + Send + Sync>>;

/// Parse one Archive with each of the six public parse functions.
///
/// The first entry, `memchr`, is the default strategy and the reference
/// `assert_all_agree` compares the others against. The in-memory variants
/// read the file only when their turn comes, so a real ~1 GB Archive is
/// held in RAM once at a time.
pub fn parse_with_every_function(path: &Path) -> Vec<(&'static str, Snapshot)> {
    let archive_name = path.file_name().unwrap().to_string_lossy().into_owned();
    let onion_re = Regex::new(ONION_PATTERN).unwrap();
    let read = || fs::read(path).unwrap();

    // `vec![...]` evaluates its elements in order, so the six parses run
    // one after another.
    vec![
        timed("memchr", || parse_warc_memchr(path)),
        timed("bytes", || parse_warc_bytes(path)),
        timed("mmap", || parse_warc_mmap(path)),
        timed("memchr/memory", || {
            parse_warc_memchr_from_memory(read(), &archive_name)
        }),
        timed("bytes/memory", || {
            parse_warc_bytes_from_memory(read(), &archive_name)
        }),
        timed("baseline", || parse_warc(path, &onion_re)),
    ]
}

/// Run one parse function, report its counts and duration on stderr.
///
/// The test harness captures stderr unless run with `-- --nocapture`.
fn timed(name: &'static str, parse: impl FnOnce() -> ParseOutcome) -> (&'static str, Snapshot) {
    let start = Instant::now();
    let result = parse().unwrap_or_else(|e| panic!("`{name}` failed: {e}"));
    eprintln!(
        "{name:>14}: {} onion(s), {} favicon URL(s), {} inline favicon(s) in {:.1?}",
        result.onions.len(),
        result.favicon_urls.len(),
        result.inline_favicons.len(),
        start.elapsed()
    );
    (name, Snapshot::from(result))
}

/// Panic unless every Snapshot equals the first one.
///
/// On a real Archive the maps hold tens of thousands of entries, so instead
/// of `assert_eq!` dumping all of them, the message lists only the first few
/// differing keys of each map.
pub fn assert_all_agree(results: &[(&str, Snapshot)]) {
    let (reference_name, reference) = &results[0];
    let report: String = results[1..]
        .iter()
        .filter(|(_, snapshot)| snapshot != reference)
        .map(|(name, snapshot)| {
            let mut section = format!("`{name}` differs from `{reference_name}`:\n");
            diff_map("onions", &reference.onions, &snapshot.onions, &mut section);
            diff_map(
                "favicon_urls",
                &reference.favicon_urls,
                &snapshot.favicon_urls,
                &mut section,
            );
            diff_map(
                "inline_favicons",
                &reference.inline_favicons,
                &snapshot.inline_favicons,
                &mut section,
            );
            section
        })
        .collect();
    assert!(report.is_empty(), "parse functions disagree:\n{report}");
}

/// How many differing keys per map `assert_all_agree` prints.
const MAX_EXAMPLES: usize = 5;

/// Append the keys whose sightings differ between `expected` and `actual`.
fn diff_map<K: Ord + Debug>(
    field: &str,
    expected: &BTreeMap<K, Vec<Sighting>>,
    actual: &BTreeMap<K, Vec<Sighting>>,
    out: &mut String,
) {
    let keys: BTreeSet<&K> = expected.keys().chain(actual.keys()).collect();
    let differing: Vec<&K> = keys
        .into_iter()
        .filter(|key| expected.get(key) != actual.get(key))
        .collect();

    // `writeln!` into a `String` (via `fmt::Write`) cannot fail, hence `unwrap`.
    for key in differing.iter().take(MAX_EXAMPLES) {
        writeln!(
            out,
            "  {field} {}\n    expected: {}\n    actual:   {}",
            shorten(key),
            shorten(&expected.get(key)),
            shorten(&actual.get(key)),
        )
        .unwrap();
    }
    if differing.len() > MAX_EXAMPLES {
        writeln!(
            out,
            "  ... and {} more differing {field} key(s)",
            differing.len() - MAX_EXAMPLES
        )
        .unwrap();
    }
}

/// Longest `Debug` text `shorten` keeps (favicon bytes can be KBs).
const MAX_DEBUG_CHARS: usize = 200;

/// `Debug`-format a value, cut to `MAX_DEBUG_CHARS` characters.
fn shorten(value: &impl Debug) -> String {
    let text = format!("{value:?}");
    if text.chars().count() <= MAX_DEBUG_CHARS {
        text
    } else {
        text.chars().take(MAX_DEBUG_CHARS).collect::<String>() + "..."
    }
}
