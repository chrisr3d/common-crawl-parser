// Tests of `save_images`, which `--save-images <dir>` runs on each Shard's
// inline favicons before the pair is marked done.
//
// The layout, `<dir>/<first two hex digits of the SHA-256>/<SHA-256>`, is
// written out here rather than taken from the library: whoever reads the
// saved images relies on it.

// Each test crate compiles its own copy of `common` and uses only part of
// it; `allow` silences the dead-code warnings for the rest.
#[allow(dead_code)]
mod common;

use std::fs;
use std::path::{Path, PathBuf};

use cc_extract::InlineFavicons;
use cc_extract::favicon_search::InlineImage;
use cc_extract::inline_favicon::{InlineFavicon, save_images, sha256_hex};
use common::file_names;

/// A fresh, empty directory for `test_name` to save images in. It doesn't
/// exist yet: `save_images` creates it.
fn images_dir(test_name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(test_name);
    // Start clean: a previous aborted run may have left files behind.
    let _ = fs::remove_dir_all(&dir);
    dir.join("images")
}

/// Inline favicons holding each of `images`, under their SHA-256.
fn favicons(images: &[&[u8]]) -> InlineFavicons {
    images
        .iter()
        .map(|bytes| {
            let image = InlineImage {
                media_type: "image/png".to_string(),
                bytes: bytes.to_vec(),
            };
            (sha256_hex(bytes), InlineFavicon::new(image))
        })
        .collect()
}

const FIRST: &[u8] = b"\x89PNG\r\n\x1a\n first made-up image";
const SECOND: &[u8] = b"GIF89a second made-up image";

/// Each image is saved under its SHA-256, holding its exact bytes, and
/// nothing else is left: no temporary file, no other subdirectory.
#[test]
fn each_image_is_saved_under_its_sha256_and_nothing_else() {
    let dir = images_dir("each_image_is_saved_under_its_sha256_and_nothing_else");

    let saved = save_images(&dir, &favicons(&[FIRST, SECOND])).unwrap();

    assert_eq!(saved, 2);
    let mut subdirectories = Vec::new();
    for bytes in [FIRST, SECOND] {
        let sha256 = sha256_hex(bytes);
        let subdirectory = dir.join(&sha256[..2]);
        assert_eq!(fs::read(subdirectory.join(&sha256)).unwrap(), bytes);
        // No temporary file left beside it.
        assert_eq!(file_names(&subdirectory), [sha256.as_str()]);
        subdirectories.push(sha256[..2].to_string());
    }
    subdirectories.sort();
    assert_eq!(file_names(&dir), subdirectories);
}

/// An image already on disk is left as it is: the file at an image's name
/// was renamed there whole, so it holds the image already.
#[test]
fn an_image_already_on_disk_is_not_rewritten() {
    let dir = images_dir("an_image_already_on_disk_is_not_rewritten");
    let sha256 = sha256_hex(FIRST);
    let path = dir.join(&sha256[..2]).join(&sha256);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "written before").unwrap();

    let saved = save_images(&dir, &favicons(&[FIRST])).unwrap();

    assert_eq!(saved, 0);
    assert_eq!(fs::read_to_string(&path).unwrap(), "written before");
    assert_eq!(file_names(path.parent().unwrap()), [sha256]);
}

/// An image that can't be written fails the call, the message naming where
/// it was to go: here a regular file stands where its subdirectory should.
#[test]
fn an_image_that_cannot_be_saved_fails_naming_its_path() {
    let dir = images_dir("an_image_that_cannot_be_saved_fails_naming_its_path");
    let sha256 = sha256_hex(FIRST);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(&sha256[..2]), "not a directory").unwrap();

    let error = save_images(&dir, &favicons(&[FIRST])).unwrap_err();

    let path = dir.join(&sha256[..2]).join(&sha256);
    assert!(
        error.to_string().contains(&path.display().to_string()),
        "the message should name {}: {error}",
        path.display()
    );
}
