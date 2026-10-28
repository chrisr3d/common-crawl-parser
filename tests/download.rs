// Tests for saving a downloaded Archive to `download/`.
//
// The crawl takes a file at an Archive's name in `download/` as that
// Archive, complete: it parses it instead of downloading it again. So the
// bytes may reach that name only once all of them arrived. These tests hand
// `save_archive` the body as a stream of chunks, the way the HTTP client
// delivers it, so no network is needed.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use cc_extract::save_archive;
use futures::stream::{self, StreamExt};

const ARCHIVE_NAME: &str = "CC-MAIN-20250101000000-20250101010101-00000.warc.wat.gz";

/// An empty `download/` directory of its own for `test_name`, inside
/// Cargo's scratch directory for integration tests.
fn download_dir(test_name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(test_name)
        .join("download");
    // Start clean: a previous aborted run may have left files behind.
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// The names of the files in `dir`.
fn file_names(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

#[tokio::test]
async fn archive_appears_at_its_name_only_once_complete() {
    let dir = download_dir("archive_appears_at_its_name_only_once_complete");
    let local_path = dir.join(ARCHIVE_NAME);
    let chunks = [b"first ".to_vec(), b"second ".to_vec(), b"last".to_vec()];
    // The stream is asked for each chunk once the ones before it are
    // written: the Archive's name must still be free then.
    let body = stream::iter(chunks.clone()).map(|chunk| {
        assert!(!local_path.exists(), "the Archive appeared before its end");
        Ok::<_, io::Error>(chunk)
    });

    let length = chunks.concat().len() as u64;
    save_archive(body, Some(length), &local_path).await.unwrap();

    assert_eq!(fs::read(&local_path).unwrap(), b"first second last");
    assert_eq!(file_names(&dir), [ARCHIVE_NAME]);
}

/// Fewer bytes than the `Content-Length` the server announced: the
/// connection was cut, and the Archive is cut short.
#[tokio::test]
async fn download_short_of_its_content_length_leaves_nothing() {
    let dir = download_dir("download_short_of_its_content_length_leaves_nothing");
    let body = stream::iter([Ok::<_, io::Error>(b"cut short".to_vec())]);

    let saved = save_archive(body, Some(1_000), &dir.join(ARCHIVE_NAME)).await;

    assert!(saved.is_err());
    assert!(file_names(&dir).is_empty(), "{:?}", file_names(&dir));
}

#[tokio::test]
async fn download_failing_part_way_leaves_nothing() {
    let dir = download_dir("download_failing_part_way_leaves_nothing");
    let body = stream::iter([
        Ok(b"first ".to_vec()),
        Err(io::Error::other("connection reset")),
    ]);

    let saved = save_archive(body, None, &dir.join(ARCHIVE_NAME)).await;

    assert!(saved.is_err());
    assert!(file_names(&dir).is_empty(), "{:?}", file_names(&dir));
}
