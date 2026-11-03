// How an Archive that can't be parsed fails.
//
// A failure coming from the Archive's own bytes (not gzip, cut short, a
// malformed record) comes back on every run: it counts toward giving the
// Archive up, and so does a panic its bytes trigger. One coming from a local
// file (missing, unreadable, the mmap copy that can't be created) says
// nothing about the Archive, and doesn't count. Every Transport must tell
// the two apart.

// Each test crate compiles its own copy of `common` and uses only part of
// it; `allow` silences the dead-code warnings for the rest.
#[allow(dead_code)]
mod common;

use std::fs;
use std::panic;
use std::path::PathBuf;
use std::process;

use cc_extract::{Format, ParseError, Shard, Transport, parse_archive};
use common::{WarcBuilder, gzip_member, http_response, on_every_transport, write_archive};

const ARCHIVE_NAME: &str = "CC-MAIN-20250101000000-20250101010101-00000.warc.gz";

/// A WARC Archive with one HTML page.
fn archive() -> Vec<u8> {
    WarcBuilder::new()
        .response(
            "https://example.com/",
            "2025-01-01T00:00:01Z",
            &http_response(&[("Content-Type", "text/html")], "<html></html>"),
        )
        .finish()
}

/// The error of parsing `transport` as a WARC Archive. Panics if it parses.
fn parse_error(transport: Transport) -> ParseError {
    let shard = Shard::from_archive_name(ARCHIVE_NAME);
    parse_archive(transport, Format::Warc, &shard, &mut []).expect_err("the parse should fail")
}

#[test]
fn corrupt_bytes_fail_in_a_way_that_repeats() {
    let mut cut_short = archive();
    cut_short.truncate(cut_short.len() / 2);
    let cases = [
        (
            "not_gzip",
            b"plain text where a gzip header should be".to_vec(),
        ),
        // Shorter than a gzip header.
        ("too_short", b"not gzip".to_vec()),
        ("cut_short", cut_short),
    ];

    for (case, bytes) in cases {
        let test_name = format!("corrupt_bytes_{case}");
        for (transport_name, transport) in on_every_transport(&test_name, ARCHIVE_NAME, &bytes) {
            let error = parse_error(transport);
            assert!(error.repeats(), "{case} on {transport_name}: {error}");
            // Where in the Archive: some byte of its size.
            let message = error.to_string();
            let (_, size) = position(&message);
            assert_eq!(
                size,
                bytes.len() as u64,
                "{case} on {transport_name}: {message}"
            );
        }
    }
}

/// The gzip stream may end cleanly with the last record unfinished: its
/// last member holds only the start of it. However the record is cut, and
/// whether its body is read or passed over, that is the Archive's bytes
/// failing, with the same message on every Transport: the record parsers
/// must not read it as the end of the records.
///
/// A body declared larger than any memory is read as far as the data
/// goes, never reserved at the length it declares: the data ends inside
/// it too.
#[test]
fn a_record_cut_short_fails_in_a_way_that_repeats() {
    let larger_than_memory = format!(
        "WARC/1.0\r\nWARC-Type: response\r\nContent-Length: {}\r\n\r\nHTTP/1.1 200 OK\r\n",
        usize::MAX
    );
    let cases: [(&str, &[u8]); 5] = [
        (
            "in_its_headers",
            b"WARC/1.0\r\nWARC-Type: response\r\nContent-Len",
        ),
        // Inside the blank line ending the headers: the record is cut even
        // with no body to come.
        (
            "in_its_blank_line",
            b"WARC/1.0\r\nWARC-Type: warcinfo\r\nContent-Length: 0\r\n\r",
        ),
        // A record of a type the parsers skip, its body passed over unread.
        (
            "in_a_passed_over_body",
            b"WARC/1.0\r\nWARC-Type: request\r\nContent-Length: 100\r\n\r\nGET / HTTP/1.1\r\n",
        ),
        (
            "in_a_read_body",
            b"WARC/1.0\r\nWARC-Type: response\r\nContent-Length: 100\r\n\r\nHTTP/1.1 200 OK\r\n",
        ),
        (
            "in_a_body_larger_than_memory",
            larger_than_memory.as_bytes(),
        ),
    ];

    for (case, cut_record) in cases {
        let mut bytes = archive();
        bytes.extend(gzip_member(cut_record));
        let test_name = format!("a_record_cut_short_{case}");
        for (transport_name, transport) in on_every_transport(&test_name, ARCHIVE_NAME, &bytes) {
            let error = parse_error(transport);
            assert!(error.repeats(), "{case} on {transport_name}: {error}");
            assert_eq!(
                error.to_string(),
                format!(
                    "the Archive ends inside a record (at byte {0} of {0})",
                    bytes.len()
                ),
                "{case} on {transport_name}"
            );
        }
    }
}

/// A record's `Content-Length` must be a number of bytes: ASCII digits,
/// with only whitespace around them, few enough to count. One that isn't,
/// or none at all, leaves no way to tell where the body ends: that fails
/// the Archive whatever the record's type, with the same message on every
/// Transport.
#[test]
fn a_malformed_content_length_fails_in_a_way_that_repeats() {
    let cases = [
        (
            "not_digits",
            "Content-Length: 12a3\r\n",
            r#"a record's Content-Length is not a byte count: "12a3""#,
        ),
        (
            "negative",
            "Content-Length: -5\r\n",
            r#"a record's Content-Length is not a byte count: "-5""#,
        ),
        (
            "empty",
            "Content-Length:\r\n",
            r#"a record's Content-Length is not a byte count: """#,
        ),
        // More than any `usize` can hold.
        (
            "overflowing",
            "Content-Length: 99999999999999999999999\r\n",
            r#"a record's Content-Length is not a byte count: "99999999999999999999999""#,
        ),
        ("missing", "", "a record has no Content-Length"),
    ];

    for (case, content_length, expected) in cases {
        // A record the parsers read, and one whose body they pass over.
        for warc_type in ["response", "request"] {
            let record =
                format!("WARC/1.0\r\nWARC-Type: {warc_type}\r\n{content_length}\r\nhello\r\n\r\n");
            let mut bytes = archive();
            bytes.extend(gzip_member(record.as_bytes()));
            let test_name = format!("a_malformed_content_length_{case}_{warc_type}");
            for (transport_name, transport) in on_every_transport(&test_name, ARCHIVE_NAME, &bytes)
            {
                let error = parse_error(transport);
                assert!(
                    error.repeats(),
                    "{case} in a {warc_type} on {transport_name}: {error}"
                );
                assert_eq!(
                    error.to_string(),
                    format!("{expected} (at byte {0} of {0})", bytes.len()),
                    "{case} in a {warc_type} on {transport_name}"
                );
            }
        }
    }
}

/// A panic while parsing an Archive is a bug its bytes trigger: parsing
/// them again panics again, so it counts toward giving the Archive up,
/// and its message says what happened, whatever the panic carries.
#[test]
fn a_panic_while_parsing_repeats() {
    let cases: [(&str, fn()); 3] = [
        ("a literal", || panic!("capacity overflow")),
        ("a formatted message", || panic!("index {} out of range", 9)),
        // Neither a `&str` nor a `String`.
        ("another value", || panic::panic_any(42)),
    ];
    let expected = [
        "the parser panicked: capacity overflow",
        "the parser panicked: index 9 out of range",
        "the parser panicked: Box<dyn Any>",
    ];

    for ((case, parse), expected) in cases.into_iter().zip(expected) {
        let payload = panic::catch_unwind(parse).expect_err(case);
        let error = ParseError::from_panic(payload);
        assert!(error.repeats(), "{case}: {error}");
        assert_eq!(error.to_string(), expected, "{case}");
    }
}

/// `len` bytes that gzip can't compress, different for each `seed`: an
/// xorshift generator's output.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

/// The position a `Corrupt` error's message ends with, `(at byte X of Y)`,
/// as `(X, Y)`. Panics if it has none.
fn position(message: &str) -> (u64, u64) {
    let start = message.rfind("(at byte ").expect(message);
    let numbers = message[start + "(at byte ".len()..]
        .strip_suffix(')')
        .expect(message);
    let (at, size) = numbers.split_once(" of ").expect(message);
    (at.parse().expect(message), size.parse().expect(message))
}

/// A gzip member damaged in the middle of the Archive fails where it is, not
/// at the end: the position the error gives lies past the damage, by at most
/// the rest of its member (whose checksum is checked at its end) and one
/// read of the gzip decoder, 32 KiB. So the Archive is a few times that, in
/// records gzip can't shrink.
#[test]
fn a_member_damaged_in_the_middle_fails_where_it_is() {
    const PAGE_SIZE: usize = 64 * 1024;
    let members: Vec<Vec<u8>> = (1..=3)
        .map(|n| {
            let page_url = format!("https://example.com/{n}");
            WarcBuilder::new()
                .response(&page_url, "2025-01-01T00:00:01Z", &noise(n, PAGE_SIZE))
                .finish()
        })
        .collect();
    let middle_of_second = members[0].len() + members[1].len() / 2;
    let end_of_second = members[0].len() + members[1].len();
    let mut bytes = members.concat();
    for byte in &mut bytes[middle_of_second..middle_of_second + 16] {
        *byte = !*byte;
    }

    let messages: Vec<(&str, String)> =
        on_every_transport("a_member_damaged", ARCHIVE_NAME, &bytes)
            .into_iter()
            .map(|(transport_name, transport)| {
                let error = parse_error(transport);
                assert!(error.repeats(), "on {transport_name}: {error}");
                (transport_name, error.to_string())
            })
            .collect();

    let (_, disk) = &messages[0];
    let (at, size) = position(disk);
    assert_eq!(size, bytes.len() as u64, "{disk}");
    let latest = (end_of_second + 32 * 1024) as u64;
    assert!(
        middle_of_second as u64 <= at && at <= latest && latest < size,
        "{disk}"
    );
    for (transport_name, message) in &messages[1..] {
        assert_eq!(message, disk, "{transport_name} differs from disk");
    }
}

/// An empty scratch directory for `test_name`.
fn scratch_dir(test_name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(test_name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn local_file_failures_do_not_repeat() {
    let dir = scratch_dir("local_file_failures_do_not_repeat");
    let missing = dir.join(ARCHIVE_NAME);
    // A directory opens as a file does, then fails on the first read.
    let directory = dir.join("directory").join(ARCHIVE_NAME);
    fs::create_dir_all(&directory).unwrap();

    let cases = [
        ("missing, disk", Transport::Disk(missing.clone())),
        ("missing, mmap", Transport::Mmap(missing)),
        ("a directory, disk", Transport::Disk(directory.clone())),
        ("a directory, mmap", Transport::Mmap(directory)),
    ];
    for (case, transport) in cases {
        let error = parse_error(transport);
        assert!(!error.repeats(), "{case}: {error}");
        // The Archive's bytes are not to blame: no position in them.
        assert!(!error.to_string().contains("at byte"), "{case}: {error}");
    }
}

/// The mmap Transport decompresses the Archive to a copy of its own,
/// `<file name>.<process id>.mmap` beside it, never opening a file already
/// there: one in the way fails the parse, and the Archive is not to blame.
#[test]
fn an_mmap_copy_that_cannot_be_created_does_not_repeat() {
    let path = write_archive(
        "an_mmap_copy_that_cannot_be_created_does_not_repeat",
        ARCHIVE_NAME,
        &archive(),
    );
    let copy_name = format!("{ARCHIVE_NAME}.{}.mmap", process::id());
    fs::write(path.with_file_name(copy_name), "in the way").unwrap();

    let error = parse_error(Transport::Mmap(path));

    assert!(!error.repeats(), "{error}");
    assert!(!error.to_string().contains("at byte"), "{error}");
}
