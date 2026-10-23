// Tests for the state kept in the output directory.
//
// A crawl loads `onions.json` / `favicons.json`, merges new Sightings in,
// and saves the files back. If an existing file could not be read and
// loading quietly returned an empty map, that save would overwrite it with
// only the new results. Loading must fail instead.
//
// `processed.log` records which (Shard, Artifact kind) pairs are done, one
// `<shard> <kind>` line each.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use cc_extract::{
    ArtifactKind, PROCESSED_FILENAME, Shard, Sightings, load_processed_from, load_sightings_from,
    save_then_mark,
};

/// An empty output directory of its own for `test_name`, inside Cargo's
/// scratch directory for integration tests.
fn output_dir(test_name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(test_name);
    // Start clean: a previous aborted run may have left files behind.
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A results file in the shape written before Sightings: `url` and
/// `archive` instead of `page_url` and `shard`.
const OLD_FORMAT: &str = r#"{
  "abcdefghijklmnop.onion": [
    {
      "url": "https://example.com/",
      "date": "2025-01-01T00:00:00Z",
      "archive": "CC-MAIN-20250101000000-20250101010101-00000.warc.gz"
    }
  ]
}"#;

#[test]
fn old_format_results_fail_to_load_naming_the_file() {
    let dir = output_dir("old_format_results_fail_to_load_naming_the_file");
    for kind in ArtifactKind::all() {
        fs::write(dir.join(kind.output_filename()), OLD_FORMAT).unwrap();
    }
    let dir = dir.to_str().unwrap();

    for &kind in ArtifactKind::all() {
        let error = load_sightings_from(kind, dir).unwrap_err();
        assert!(error.to_string().contains(kind.output_filename()));
    }
}

#[test]
fn missing_results_load_as_empty() {
    let dir = output_dir("missing_results_load_as_empty");
    let dir = dir.to_str().unwrap();

    for &kind in ArtifactKind::all() {
        assert!(load_sightings_from(kind, dir).unwrap().is_empty());
    }
}

#[test]
fn processed_log_ignores_lines_without_a_known_kind() {
    let dir = output_dir("processed_log_ignores_lines_without_a_known_kind");
    fs::write(
        dir.join(PROCESSED_FILENAME),
        // A bare Archive name, as written before kinds were tracked: it says
        // nothing about which kinds were extracted, so it marks nothing.
        "CC-MAIN-20250101000000-20250101010101-00000.warc.gz\n\
         CC-MAIN-20250101000000-20250101010101-00001 onion\n\
         CC-MAIN-20250101000000-20250101010101-00002 not-a-kind\n",
    )
    .unwrap();

    let processed = load_processed_from(dir.to_str().unwrap());

    assert_eq!(
        processed,
        HashSet::from([(
            Shard::from_archive_name("CC-MAIN-20250101000000-20250101010101-00001"),
            ArtifactKind::Onion
        )])
    );
}

/// A pair is marked done only once its results are saved. Were it the other
/// way round, a crash or a failed write between the two steps would leave
/// the pair marked but its Sightings lost, and no later run would redo it.
#[test]
fn failed_save_leaves_the_pair_unmarked() {
    let dir = output_dir("failed_save_leaves_the_pair_unmarked");
    // A directory where `onions.json` should be written makes the save
    // fail, even for a user that file permissions wouldn't stop.
    fs::create_dir(dir.join(ArtifactKind::Onion.output_filename())).unwrap();
    let dir = dir.to_str().unwrap();
    let shard = Shard::from_archive_name("CC-MAIN-20250101000000-20250101010101-00000");

    let saved = save_then_mark(ArtifactKind::Onion, &Sightings::new(), &shard, dir);

    assert!(saved.is_err());
    assert!(load_processed_from(dir).is_empty());
}
