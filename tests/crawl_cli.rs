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

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use cc_extract::{ArtifactKind, PROCESSED_FILENAME, Sightings, load_sightings_from};
use common::{WarcBuilder, http_response};

/// File name of the fixture Archive.
const ARCHIVE_NAME: &str = "CC-MAIN-20250101000000-20250101010101-00000.warc.gz";

/// The paths file line for the fixture. Only its file name is used: the
/// Archive is already in `download/`.
const ARCHIVE_URI: &str = "crawl-data/CC-MAIN-2025-01/segments/1735000000000.00/warc/\
                           CC-MAIN-20250101000000-20250101010101-00000.warc.gz";

/// One HTML page with one onion and one declared favicon.
fn fixture_archive() -> Vec<u8> {
    let page = r#"<html><head><link rel="icon" href="/icon.png"></head>
<body>Mirror: duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion</body></html>"#;
    WarcBuilder::new()
        .response(
            "https://example.com/",
            "2025-01-01T00:00:01Z",
            &http_response(&[("Content-Type", "text/html")], page),
        )
        .finish()
}

/// A fresh working directory for `test_name`: the fixture in `download/`
/// and a `warc.paths` file listing it.
fn workspace(test_name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(test_name);
    // Start clean: a previous aborted run may have left files behind.
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("download")).unwrap();
    fs::write(dir.join("download").join(ARCHIVE_NAME), fixture_archive()).unwrap();
    fs::write(dir.join("warc.paths"), format!("{ARCHIVE_URI}\n")).unwrap();
    dir
}

/// Run the binary in `workspace` on its `warc.paths` with `args`, and
/// return what it printed on stderr. Panics if it fails.
fn crawl(workspace: &Path, args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_cc-extract"))
        .current_dir(workspace)
        .arg("warc.paths")
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
#[test]
fn adding_a_kind_later_runs_only_that_kind() {
    let dir = workspace("adding_a_kind_later_runs_only_that_kind");

    crawl(&dir, &["-e", "onion", "--output-dir", "stepwise"]);
    let second_run = crawl(&dir, &["-e", "onion,favicon", "--output-dir", "stepwise"]);
    crawl(&dir, &["-e", "onion,favicon", "--output-dir", "at_once"]);

    assert!(
        second_run.contains(&format!("{ARCHIVE_NAME}: extracting favicon\n")),
        "second run should extract favicon only:\n{second_run}"
    );
    let stepwise = saved_state(&dir.join("stepwise"));
    assert_eq!(stepwise, saved_state(&dir.join("at_once")));
    // The fixture's onion and favicon really were found.
    assert!(stepwise.0.iter().all(|sightings| sightings.len() == 1));
}
