// End-to-end tests of the `cc-extract` binary.
//
// The crawl pipeline (which kinds run on which Shard, when results are
// saved and marked) lives in `main.rs`, so these tests run the compiled
// binary the way a user does. Cargo builds the package's binaries before
// its integration tests and passes each one's path to them at compile time
// as `CARGO_BIN_EXE_<name>`.
//
// No network: the binary skips downloading an Archive that is already in
// `download/` under its working directory. Each test puts the fixture there
// and runs the binary from a scratch directory of its own.

// Each test crate compiles its own copy of `common` and uses only part of
// it; `allow` silences the dead-code warnings for the rest.
#[allow(dead_code)]
mod common;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use cc_extract::{
    ArtifactKind, PROCESSED_FILENAME, Shard, Sighting, Sightings, load_sightings_from,
};
use common::{WarcBuilder, http_response, wat_response_json};
use serde_json::json;

/// File names of the fixture Shard's Archives, one per Format.
const WARC_NAME: &str = "CC-MAIN-20250101000000-20250101010101-00000.warc.gz";
const WAT_NAME: &str = "CC-MAIN-20250101000000-20250101010101-00000.warc.wat.gz";
const WET_NAME: &str = "CC-MAIN-20250101000000-20250101010101-00000.warc.wet.gz";

/// The Shard the fixture Archives belong to.
const SHARD: &str = "CC-MAIN-20250101000000-20250101010101-00000";

/// The paths file line for the fixture: its WARC Archive, from which the
/// binary derives the others' paths. Only the file names are used: the
/// Archives a test needs are already in `download/`.
const ARCHIVE_URI: &str = "crawl-data/CC-MAIN-2025-01/segments/1735000000000.00/warc/\
                           CC-MAIN-20250101000000-20250101010101-00000.warc.gz";

/// The fixture's one page.
const PAGE: &str = "https://example.com/";
const DATE: &str = "2025-01-01T00:00:01Z";
/// v3, in the page's `Onion-Location` HTTP header: kept by WAT.
const HEADER_ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";
/// v3, in the page's text: kept by WET.
const TEXT_ONION: &str = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";

/// The page as a WARC Archive: one HTML page with two onions and one
/// declared favicon.
fn warc_archive() -> Vec<u8> {
    let page = format!(
        r#"<html><head><link rel="icon" href="/icon.png"></head>
<body>Mirror: {TEXT_ONION}</body></html>"#
    );
    let onion_location = format!("http://{HEADER_ONION}/");
    let headers = [
        ("Content-Type", "text/html"),
        ("Onion-Location", &onion_location),
    ];
    WarcBuilder::new()
        .response(PAGE, DATE, &http_response(&headers, &page))
        .finish()
}

/// The same page as a WAT Archive: its headers and `<head>` tags.
fn wat_archive() -> Vec<u8> {
    let onion_location = format!("http://{HEADER_ONION}/");
    let headers = [
        ("Content-Type", "text/html"),
        ("Onion-Location", &onion_location),
    ];
    let html_metadata = json!({
        "Head": {"Link": [{"path": "LINK@/href", "url": "/icon.png", "rel": "icon"}]},
        "Links": [],
    });
    let json = wat_response_json(PAGE, DATE, &headers, Some(html_metadata));
    WarcBuilder::new()
        .wat_metadata(PAGE, "2025-01-09T00:00:00Z", &json)
        .finish()
}

/// The same page as a WET Archive: its text.
fn wet_archive() -> Vec<u8> {
    WarcBuilder::new()
        .conversion(PAGE, DATE, &format!("Mirror: {TEXT_ONION}\n"))
        .finish()
}

/// What a crawl of the fixture saves for each kind (in `ArtifactKind::all`
/// order), whichever Formats it reads.
fn expected_sightings() -> Vec<Sightings> {
    let on_page = || {
        vec![Sighting {
            page_url: PAGE.to_string(),
            date: DATE.to_string(),
            shard: Shard::from_archive_name(SHARD),
        }]
    };
    vec![
        HashMap::from([
            (HEADER_ONION.to_string(), on_page()),
            (TEXT_ONION.to_string(), on_page()),
        ]),
        HashMap::from([("https://example.com/icon.png".to_string(), on_page())]),
    ]
}

/// A fresh working directory for `test_name`: `archives` in `download/`
/// and a `warc.paths` file listing the fixture Shard.
fn workspace(test_name: &str, archives: &[(&str, Vec<u8>)]) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(test_name);
    // Start clean: a previous aborted run may have left files behind.
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("download")).unwrap();
    for (file_name, bytes) in archives {
        fs::write(dir.join("download").join(file_name), bytes).unwrap();
    }
    fs::write(dir.join("warc.paths"), format!("{ARCHIVE_URI}\n")).unwrap();
    dir
}

/// The binary, set to run in `workspace` on its `warc.paths`.
fn cc_extract(workspace: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cc-extract"));
    command.current_dir(workspace).arg("warc.paths");
    command
}

/// Run the binary in `workspace` on its `warc.paths` with `args`, and
/// return what it printed on stderr. Panics if it fails.
fn crawl(workspace: &Path, args: &[&str]) -> String {
    let output = cc_extract(workspace)
        .args(["--jobs", "1"])
        .args(args)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "cc-extract failed:\n{stderr}");
    stderr
}

/// What a run leaves in `output_dir`: every kind's Sightings, and the
/// `processed.log` lines, sorted.
///
/// Compared loaded rather than byte for byte: a `HashMap` is saved in an
/// order that changes from run to run, and `processed.log` lines are
/// appended run after run, so their order depends on which runs wrote them.
fn saved_state(output_dir: &Path) -> (Vec<Sightings>, Vec<String>) {
    let dir = output_dir.to_str().unwrap();
    let sightings = ArtifactKind::all()
        .iter()
        .map(|&kind| load_sightings_from(kind, dir).unwrap())
        .collect();
    let mut processed: Vec<String> = fs::read_to_string(output_dir.join(PROCESSED_FILENAME))
        .unwrap()
        .lines()
        .map(String::from)
        .collect();
    processed.sort();
    (sightings, processed)
}

/// ADR-0002: a kind added later runs alone on a Shard already done for the
/// others, and ends up with the same files as asking for every kind at once.
///
/// Every run reads WARC (`--formats warc`), the one Format both kinds can
/// share: the test is about kinds, not Formats.
#[test]
fn adding_a_kind_later_runs_only_that_kind() {
    let dir = workspace(
        "adding_a_kind_later_runs_only_that_kind",
        &[(WARC_NAME, warc_archive())],
    );
    let crawl_warc = |args: &[&str]| crawl(&dir, &[&["--formats", "warc"][..], args].concat());

    crawl_warc(&["-e", "onion", "--output-dir", "stepwise"]);
    let second_run = crawl_warc(&["-e", "onion,favicon", "--output-dir", "stepwise"]);
    crawl_warc(&["-e", "onion,favicon", "--output-dir", "at_once"]);

    assert!(
        second_run.contains(&format!("{SHARD}: extracting favicon from warc\n")),
        "second run should extract favicon only:\n{second_run}"
    );
    let stepwise = saved_state(&dir.join("stepwise"));
    assert_eq!(stepwise, saved_state(&dir.join("at_once")));
    // The fixture's onions and favicon really were found.
    assert_eq!(stepwise.0, expected_sightings());
}

/// ADR-0001: on CC-MAIN, `onion` and `favicon` are read from WAT + WET,
/// derived from the WARC paths file line, and give what WARC gives. The
/// WARC Archive is not in `download/`: fetching it would fail the run.
#[test]
fn default_kinds_read_wat_and_wet() {
    let dir = workspace(
        "default_kinds_read_wat_and_wet",
        &[(WAT_NAME, wat_archive()), (WET_NAME, wet_archive())],
    );

    let stderr = crawl(&dir, &[]);

    assert!(
        stderr.contains(&format!("{SHARD}: extracting onion,favicon from wat,wet\n")),
        "the Plan should be WAT + WET:\n{stderr}"
    );
    assert_eq!(
        saved_state(&dir.join("output")),
        (
            expected_sightings(),
            vec![format!("{SHARD} favicon"), format!("{SHARD} onion")]
        )
    );
}

/// `favicon` alone is read from WAT only: the WET Archive is not in
/// `download/` either.
#[test]
fn favicon_alone_reads_only_wat() {
    let dir = workspace("favicon_alone_reads_only_wat", &[(WAT_NAME, wat_archive())]);

    let stderr = crawl(&dir, &["-e", "favicon"]);

    assert!(
        stderr.contains(&format!("{SHARD}: extracting favicon from wat\n")),
        "the Plan should be WAT:\n{stderr}"
    );
    // `expected_sightings` lists the kinds in `ArtifactKind::all` order.
    let [_, favicons]: [Sightings; 2] = expected_sightings().try_into().unwrap();
    assert_eq!(
        saved_state(&dir.join("output")),
        (
            vec![Sightings::new(), favicons],
            vec![format!("{SHARD} favicon")]
        )
    );
}

/// `--formats` that can't serve a requested kind stop the run at startup,
/// before anything is downloaded or written.
#[test]
fn formats_that_cannot_serve_a_kind_are_rejected() {
    let dir = workspace(
        "formats_that_cannot_serve_a_kind_are_rejected",
        &[(WARC_NAME, warc_archive())],
    );

    let output = cc_extract(&dir)
        .args(["--formats", "wet", "-e", "favicon"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "cc-extract should fail:\n{stderr}"
    );
    assert!(
        stderr.contains("cannot extract favicon from wet"),
        "the message should name the kind and the Formats:\n{stderr}"
    );
    assert!(!dir.join("output").exists());
}
