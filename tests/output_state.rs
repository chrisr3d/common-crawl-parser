// Tests for loading the saved results in the output directory.
//
// A crawl loads `onions.json` / `favicons.json`, merges new Sightings in,
// and saves the files back. If an existing file could not be read and
// loading quietly returned an empty map, that save would overwrite it with
// only the new results. Loading must fail instead.

use std::fs;
use std::path::PathBuf;

use onion_crawler::{FAVICONS_FILENAME, RESULTS_FILENAME, load_favicons_from, load_results_from};

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
    fs::write(dir.join(RESULTS_FILENAME), OLD_FORMAT).unwrap();
    fs::write(dir.join(FAVICONS_FILENAME), OLD_FORMAT).unwrap();
    let dir = dir.to_str().unwrap();

    let onions_error = load_results_from(dir).unwrap_err();
    assert!(onions_error.to_string().contains(RESULTS_FILENAME));

    let favicons_error = load_favicons_from(dir).unwrap_err();
    assert!(favicons_error.to_string().contains(FAVICONS_FILENAME));
}

#[test]
fn missing_results_load_as_empty() {
    let dir = output_dir("missing_results_load_as_empty");
    let dir = dir.to_str().unwrap();

    assert!(load_results_from(dir).unwrap().is_empty());
    assert!(load_favicons_from(dir).unwrap().is_empty());
}
