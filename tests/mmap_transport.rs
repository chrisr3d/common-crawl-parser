// Tests for the files the `Mmap` Transport leaves next to an Archive.
//
// The `Mmap` Transport decompresses the Archive to a copy it can map. A
// process can be killed at any moment of a parse, and a killed process runs
// no cleanup code, so whatever is visible in the Archive's directory while
// the parse runs is what a kill would leave behind: several GB for a WARC
// Archive, under a name no later run reads.

// Each test crate compiles its own copy of `common` and uses only part of
// it; `allow` silences the dead-code warnings for the rest.
#[allow(dead_code)]
mod common;

use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use cc_extract::{
    ArtifactKind, Extractor, Findings, Format, PageRecord, Shard, Transport, parse_archive,
};
use common::{WarcBuilder, http_response, write_archive};

const ARCHIVE_NAME: &str = "CC-MAIN-20250101000000-20250101010101-00000.warc.gz";

/// A WARC Archive with one HTML page, so the extractors are called once.
fn archive() -> Vec<u8> {
    WarcBuilder::new()
        .warcinfo("2025-01-01T00:00:00Z", "software: test\r\n")
        .response(
            "https://example.com/",
            "2025-01-01T00:00:01Z",
            &http_response(&[("Content-Type", "text/html")], "<html></html>"),
        )
        .finish()
}

/// The names of the files in `dir`, sorted.
fn file_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// An extractor that finds nothing: it lists `dir` when handed the first
/// page, while the parse is under way.
///
/// ## Sharing the result with `Rc<RefCell<..>>`
///
/// `parse_archive` takes the extractor as a `Box<dyn Extractor>`, and only
/// `into_findings` gets anything back out of it, as `Findings`. The test
/// keeps a second handle on the listing instead: `Rc` lets two owners share
/// one value, `RefCell` lets either of them change it through a shared
/// handle (checked at run time rather than by the borrow checker).
struct DirectoryLister {
    dir: PathBuf,
    listing: Rc<RefCell<Option<Vec<String>>>>,
}

impl Extractor for DirectoryLister {
    fn kind(&self) -> ArtifactKind {
        ArtifactKind::Onion
    }

    fn extract(&mut self, _record: &PageRecord<'_>, _shard: &Shard) {
        let mut listing = self.listing.borrow_mut();
        if listing.is_none() {
            *listing = Some(file_names(&self.dir));
        }
    }

    fn artifact_count(&self) -> usize {
        0
    }

    fn into_findings(self: Box<Self>) -> Findings {
        Findings::empty(ArtifactKind::Onion)
    }
}

/// While the Archive is being parsed, its decompressed copy has no name in
/// the directory, so a process killed then leaves only the Archive.
///
/// Unix only: Windows can't remove an open file, so there the copy keeps its
/// name until the parse ends.
#[cfg(unix)]
#[test]
fn mmap_parse_shows_only_the_archive_while_it_runs() {
    let path = write_archive(
        "mmap_parse_shows_only_the_archive_while_it_runs",
        ARCHIVE_NAME,
        &archive(),
    );
    let dir = path.parent().unwrap().to_path_buf();
    let listing = Rc::new(RefCell::new(None));
    let mut extractors: Vec<Box<dyn Extractor>> = vec![Box::new(DirectoryLister {
        dir: dir.clone(),
        listing: Rc::clone(&listing),
    })];

    parse_archive(
        Transport::Mmap(path),
        Format::Warc,
        &Shard::from_archive_name(ARCHIVE_NAME),
        &mut extractors,
    )
    .unwrap();

    assert_eq!(
        listing.borrow().as_deref(),
        Some([ARCHIVE_NAME.to_string()].as_slice()),
        "the directory during the parse"
    );
    assert_eq!(file_names(&dir), [ARCHIVE_NAME], "the directory afterwards");
}

/// An Archive cut short fails while being decompressed, and its partial
/// copy goes with the error.
#[test]
fn failed_mmap_parse_leaves_only_the_archive() {
    let mut cut_short = archive();
    cut_short.truncate(cut_short.len() / 2);
    let path = write_archive(
        "failed_mmap_parse_leaves_only_the_archive",
        ARCHIVE_NAME,
        &cut_short,
    );
    let dir = path.parent().unwrap().to_path_buf();

    let result = parse_archive(
        Transport::Mmap(path),
        Format::Warc,
        &Shard::from_archive_name(ARCHIVE_NAME),
        &mut [],
    );

    assert!(result.is_err(), "a truncated Archive should fail to parse");
    assert_eq!(file_names(&dir), [ARCHIVE_NAME]);
}
