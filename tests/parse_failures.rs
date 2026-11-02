// How an Archive that can't be parsed fails.
//
// A failure coming from the Archive's own bytes (not gzip, cut short) comes
// back on every run: it counts toward giving the Archive up. One coming from
// a local file (missing, unreadable, the mmap copy that can't be created)
// says nothing about the Archive, and doesn't count. Every Transport must
// tell the two apart.

// Each test crate compiles its own copy of `common` and uses only part of
// it; `allow` silences the dead-code warnings for the rest.
#[allow(dead_code)]
mod common;

use std::fs;
use std::path::PathBuf;
use std::process;

use cc_extract::{Format, ParseError, Shard, Transport, parse_archive};
use common::{WarcBuilder, http_response, write_archive};

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

/// `bytes` on each Transport, by name: in a file of `test_name`'s own for
/// disk and mmap.
fn on_every_transport(test_name: &str, bytes: &[u8]) -> [(&'static str, Transport); 3] {
    let path = write_archive(test_name, ARCHIVE_NAME, bytes);
    [
        ("disk", Transport::Disk(path.clone())),
        ("memory", Transport::Memory(bytes.to_vec())),
        ("mmap", Transport::Mmap(path)),
    ]
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
        for (transport_name, transport) in on_every_transport(&test_name, &bytes) {
            let error = parse_error(transport);
            assert!(error.repeats(), "{case} on {transport_name}: {error}");
        }
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
}
