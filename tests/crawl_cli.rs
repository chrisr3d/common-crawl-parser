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
//
// ## A throwaway kvrocks
//
// The crawl writes its results to a kvrocks store. The tests that run a
// crawl to the end need one, named by `CC_EXTRACT_TEST_KVROCKS` (a Unix
// socket path or a `redis://host:port` URL), and are skipped, with a message
// on stderr, when it is not set. Each of them empties the store first
// (`FLUSHDB`): the variable must name a throwaway instance, never a store
// holding results. They take turns, as they share it. If the store needs
// a password, `CC_EXTRACT_KVROCKS_PASSWORD` holds it, for the tests and the
// binary alike.
//
// The tests that stop at start-up pass a socket nothing listens on instead:
// they never reach a store.

// Each test crate compiles its own copy of `common` and uses only part of
// it; `allow` silences the dead-code warnings for the rest.
#[allow(dead_code)]
mod common;

use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, PoisonError};

use cc_extract::inline_favicon::sha256_hex;
use cc_extract::store::{PASSWORD_VARIABLE, Store};
use cc_extract::{
    ArtifactKind, Findings, InlineFavicon, KvrocksStore, Shard, Sighting, StoreAddress,
};
use common::{WarcBuilder, findings_in, http_response, normalized, wat_response_json};
use flate2::Compression;
use flate2::write::GzEncoder;
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

/// A 1×1 PNG in base64, as a page embeds it. At 96 characters, it fills
/// more than one of the 76-character lines Shodan's hash is computed on.
const PNG_BASE64: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP4z8DwHwAFAAH/VscvDQAAAABJRU5ErkJggg==";
/// The PNG's SHA-256, by Python's `hashlib.sha256(png).hexdigest()`.
const PNG_SHA256: &str = "49e1dad481e94dfab7c9573a9a81d56aa2ca629fe15a3f7a910aa4f47601c00d";
/// The PNG's Shodan favicon hash, by Python's
/// `mmh3.hash(codecs.encode(png, "base64"))`.
const PNG_MMH3: i32 = 1_932_519_735;

/// A second page, embedding the same PNG as the first.
const OTHER_PAGE: &str = "https://example.org/";
const OTHER_DATE: &str = "2025-01-01T00:00:02Z";

/// Two pages embedding the same PNG as a `data:` URI, the second with its
/// base64 cut over two lines; the first also mentions an onion.
fn inline_favicon_warc_archive() -> Vec<u8> {
    let page = format!(
        r#"<html><head><link rel="icon" href="data:image/png;base64,{PNG_BASE64}"></head>
<body>Mirror: {TEXT_ONION}</body></html>"#
    );
    let (start, end) = PNG_BASE64.split_at(40);
    let other_page = format!(
        r#"<html><head><link rel="shortcut icon" href="data:image/png;base64,{start}
{end}"></head></html>"#
    );
    let headers = [("Content-Type", "text/html")];
    WarcBuilder::new()
        .response(PAGE, DATE, &http_response(&headers, &page))
        .response(
            OTHER_PAGE,
            OTHER_DATE,
            &http_response(&headers, &other_page),
        )
        .finish()
}

/// What a crawl of the fixture finds for each kind (in `ArtifactKind::all`
/// order), whichever Formats it reads.
fn expected_sightings() -> Vec<Findings> {
    let on_page = || {
        vec![Sighting {
            page_url: PAGE.to_string(),
            date: DATE.to_string(),
            shard: Shard::from_archive_name(SHARD),
        }]
    };
    vec![
        Findings::Sightings(HashMap::from([
            (HEADER_ONION.to_string(), on_page()),
            (TEXT_ONION.to_string(), on_page()),
        ])),
        Findings::Sightings(HashMap::from([(
            "https://example.com/icon.png".to_string(),
            on_page(),
        )])),
        // No inline favicon on the page.
        Findings::empty(ArtifactKind::InlineFavicon),
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

// ---------------------------------------------------------------------------
// The test store
// ---------------------------------------------------------------------------

/// The variable naming the kvrocks the crawl tests write to. Each test
/// empties that store first.
const TEST_STORE_VARIABLE: &str = "CC_EXTRACT_TEST_KVROCKS";

/// Held by the test using the store: the others wait for it.
static STORE_TURN: Mutex<()> = Mutex::new(());

/// The kvrocks named by `TEST_STORE_VARIABLE`, emptied, for one test.
struct TestStore {
    address: StoreAddress,
    /// Store calls are async: each runs to its end on this runtime, the
    /// binary in between.
    runtime: tokio::runtime::Runtime,
    /// The test's turn, given back when it ends.
    _turn: MutexGuard<'static, ()>,
}

impl TestStore {
    /// The test store, emptied, once the tests before have finished with
    /// it; `None`, saying so on stderr, if `TEST_STORE_VARIABLE` is not set.
    fn take(test_name: &str) -> Option<Self> {
        let Ok(address) = env::var(TEST_STORE_VARIABLE) else {
            eprintln!(
                "{test_name}: skipped, set {TEST_STORE_VARIABLE} to the socket path or \
                 redis://host:port URL of a throwaway kvrocks to run it"
            );
            return None;
        };
        // A test failing while it holds the turn *poisons* the mutex; the
        // next test empties the store anyway, so it takes the turn as is.
        let turn = STORE_TURN.lock().unwrap_or_else(PoisonError::into_inner);
        let store = TestStore {
            address: address.parse().unwrap(),
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
            _turn: turn,
        };
        store.command(&["FLUSHDB"]);
        Some(store)
    }

    /// Run `command` (its name, then its arguments) on the store directly,
    /// past the crawl's own writes.
    fn command(&self, command: &[&str]) {
        self.runtime.block_on(async {
            let client = self
                .address
                .client(env::var(PASSWORD_VARIABLE).ok())
                .unwrap();
            let mut connection = client.get_multiplexed_async_connection().await.unwrap();
            let mut cmd = redis::cmd(command[0]);
            cmd.arg(&command[1..]);
            cmd.query_async::<()>(&mut connection).await.unwrap();
        });
    }

    /// What `read` gives on a connection to the store.
    fn read<T>(&self, read: impl AsyncFnOnce(&mut KvrocksStore) -> T) -> T {
        self.runtime.block_on(async {
            let password = env::var(PASSWORD_VARIABLE).ok();
            let mut store = KvrocksStore::connect(&self.address, password)
                .await
                .unwrap();
            read(&mut store).await
        })
    }

    /// The members of the set at `key`, sorted.
    fn members(&self, key: &str) -> BTreeSet<String> {
        self.read(async |store| store.members(key).await.unwrap())
            .into_iter()
            .collect()
    }

    /// The fields of the hash at `key`.
    fn fields(&self, key: &str) -> HashMap<String, String> {
        self.read(async |store| store.fields(key).await.unwrap())
    }

    /// What the runs so far left in the store: every kind's Sightings (in
    /// `ArtifactKind::all` order), and the done pairs, sorted.
    fn state(&self) -> (Vec<Findings>, Vec<String>) {
        let findings = self.read(async |store| {
            let mut findings = Vec::new();
            for &kind in ArtifactKind::all() {
                findings.push(findings_in(store, kind).await);
            }
            findings
        });
        (findings, self.members("processed").into_iter().collect())
    }
}

/// The binary, set to run in `workspace` on its `warc.paths`.
fn cc_extract(workspace: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cc-extract"));
    command.current_dir(workspace).arg("warc.paths");
    command
}

/// The binary, set to run in `workspace` on its `warc.paths`, writing to
/// `store`.
fn cc_extract_into(store: &TestStore, workspace: &Path) -> Command {
    let mut command = cc_extract(workspace);
    command.args(["--kvrocks", &store.address.to_string(), "--jobs", "1"]);
    command
}

/// Run the binary in `workspace` on its `warc.paths` with `args`, writing
/// to `store`, and return what it printed on stderr. Panics if it fails.
fn crawl(store: &TestStore, workspace: &Path, args: &[&str]) -> String {
    let output = cc_extract_into(store, workspace)
        .args(args)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "cc-extract failed:\n{stderr}");
    stderr
}

/// A socket path in `workspace` nothing listens on: a run given it stops
/// at start-up, if it gets as far as the store, without touching any.
fn no_store(workspace: &Path) -> String {
    workspace
        .join("no-store.sock")
        .to_str()
        .unwrap()
        .to_string()
}

/// The id the store gives the Page `page_url` in the fixture Shard: the
/// first 16 bytes of the SHA-256 of `"<shard> <page_url>"`, in hex.
fn page_id(page_url: &str) -> String {
    sha256_hex(format!("{SHARD} {page_url}").as_bytes())[..32].to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A kind added later runs alone on a Shard already done for the
/// others, and ends up with the same store as asking for every kind at once.
///
/// Every run reads WARC (`--formats warc`), the one Format both kinds can
/// share: the test is about kinds, not Formats.
#[test]
fn adding_a_kind_later_runs_only_that_kind() {
    let Some(store) = TestStore::take("adding_a_kind_later_runs_only_that_kind") else {
        return;
    };
    let dir = workspace(
        "adding_a_kind_later_runs_only_that_kind",
        &[(WARC_NAME, warc_archive())],
    );
    let crawl_warc =
        |args: &[&str]| crawl(&store, &dir, &[&["--formats", "warc"][..], args].concat());

    crawl_warc(&["-e", "onion"]);
    let second_run = crawl_warc(&["-e", "onion,favicon"]);
    let stepwise = store.state();
    store.command(&["FLUSHDB"]);
    crawl_warc(&["-e", "onion,favicon"]);

    assert!(
        second_run.contains(&format!("{SHARD}: extracting favicon from warc\n")),
        "second run should extract favicon only:\n{second_run}"
    );
    assert_eq!(stepwise, store.state());
    // The fixture's onions and favicon really were found.
    assert_eq!(stepwise.0, expected_sightings());
}

/// On CC-MAIN, `onion` and `favicon` are read from WAT + WET,
/// derived from the WARC paths file line, and give what WARC gives. The
/// WARC Archive is not in `download/`: fetching it would fail the run.
///
/// The results are in the store only: no results file is written where
/// the crawl runs.
#[test]
fn default_kinds_read_wat_and_wet() {
    let Some(store) = TestStore::take("default_kinds_read_wat_and_wet") else {
        return;
    };
    let dir = workspace(
        "default_kinds_read_wat_and_wet",
        &[(WAT_NAME, wat_archive()), (WET_NAME, wet_archive())],
    );

    let stderr = crawl(&store, &dir, &[]);

    assert!(
        stderr.contains(&format!("{SHARD}: extracting onion,favicon from wat,wet\n")),
        "the Plan should be WAT + WET:\n{stderr}"
    );
    assert_eq!(
        store.state(),
        (
            expected_sightings(),
            vec![format!("{SHARD} favicon"), format!("{SHARD} onion")]
        )
    );
    assert!(!dir.join("output").exists());
    let json_files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    assert!(json_files.is_empty(), "{json_files:?}");
}

/// `favicon` alone is read from WAT only: the WET Archive is not in
/// `download/` either.
#[test]
fn favicon_alone_reads_only_wat() {
    let Some(store) = TestStore::take("favicon_alone_reads_only_wat") else {
        return;
    };
    let dir = workspace("favicon_alone_reads_only_wat", &[(WAT_NAME, wat_archive())]);

    let stderr = crawl(&store, &dir, &["-e", "favicon"]);

    assert!(
        stderr.contains(&format!("{SHARD}: extracting favicon from wat\n")),
        "the Plan should be WAT:\n{stderr}"
    );
    // `expected_sightings` lists the kinds in `ArtifactKind::all` order.
    let [_, favicons, inline_favicons]: [Findings; 3] = expected_sightings().try_into().unwrap();
    assert_eq!(
        store.state(),
        (
            vec![
                Findings::empty(ArtifactKind::Onion),
                favicons,
                inline_favicons
            ],
            vec![format!("{SHARD} favicon")]
        )
    );
}

/// The exit status of a run that went to the end but left some (Shard, kind)
/// pairs undone: re-running the same command retries them.
const EXIT_UNDONE: i32 = 3;

/// An Archive that fails to parse leaves the kinds reading it undone, and
/// the run, which goes on to the end, exits with `EXIT_UNDONE`. Here the
/// WET Archive isn't gzip: `onion` (WAT + WET) is left undone, `favicon`
/// (WAT only) is done.
#[test]
fn an_archive_failing_to_parse_exits_undone() {
    let Some(store) = TestStore::take("an_archive_failing_to_parse_exits_undone") else {
        return;
    };
    let dir = workspace(
        "an_archive_failing_to_parse_exits_undone",
        &[(WAT_NAME, wat_archive()), (WET_NAME, b"not gzip".to_vec())],
    );

    let output = cc_extract_into(&store, &dir).output().unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(EXIT_UNDONE),
        "cc-extract should exit undone:\n{stderr}"
    );
    assert!(
        stderr.contains("Summary: 0 processed, 0 skipped, 1 failed"),
        "the summary should count the Shard as failed:\n{stderr}"
    );
    assert_eq!(store.state().1, [format!("{SHARD} favicon")]);
}

/// A kind whose Sightings can't be written to the store is left undone too.
/// The write fails because the fixture favicon's key, where the crawl adds
/// the Page to a set, already holds a string.
#[test]
fn a_failed_store_write_exits_undone() {
    let Some(store) = TestStore::take("a_failed_store_write_exits_undone") else {
        return;
    };
    let dir = workspace(
        "a_failed_store_write_exits_undone",
        &[(WAT_NAME, wat_archive())],
    );
    store.command(&["SET", "favicon:https://example.com/icon.png", "not a set"]);

    let output = cc_extract_into(&store, &dir)
        .args(["-e", "favicon"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(EXIT_UNDONE),
        "cc-extract should exit undone:\n{stderr}"
    );
    assert!(
        stderr.contains("Summary: 0 processed, 0 skipped, 1 failed"),
        "the summary should count the Shard as failed:\n{stderr}"
    );
    assert!(store.members("processed").is_empty());
}

/// A store that can't be reached stops the run at start-up, naming it,
/// before anything is downloaded: here the fixture Archive is not in
/// `download/`, and nothing may appear there.
#[test]
fn an_unreachable_store_stops_the_run() {
    let dir = workspace("an_unreachable_store_stops_the_run", &[]);
    let socket = no_store(&dir);

    let output = cc_extract(&dir)
        .args(["--kvrocks", &socket])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "cc-extract should fail:\n{stderr}"
    );
    assert!(
        stderr.contains(&format!("cannot reach the store at {socket}")),
        "the message should name the socket:\n{stderr}"
    );
    assert_eq!(fs::read_dir(dir.join("download")).unwrap().count(), 0);
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
        .args([
            "--formats",
            "wet",
            "-e",
            "favicon",
            "--kvrocks",
            &no_store(&dir),
        ])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "cc-extract should fail:\n{stderr}"
    );
    assert!(
        stderr.contains("cannot extract favicon from wet"),
        "the message should name the kind and the Formats:\n{stderr}"
    );
}

/// A gzipped paths file cut short (an interrupted download of it) stops the
/// run at startup, rather than being read as if its first lines were all of
/// it. The fixture Shard is the first line and its WARC Archive is in
/// `download/`, so a run that went on would process it, with `--limit 1`
/// (or stop, here, on the store it can't reach).
#[test]
fn a_paths_file_cut_short_stops_the_run() {
    let dir = workspace(
        "a_paths_file_cut_short_stops_the_run",
        &[(WARC_NAME, warc_archive())],
    );
    let lines: String = (0..2000)
        .map(|n| ARCHIVE_URI.replace("-00000.warc.gz", &format!("-{n:05}.warc.gz\n")))
        .collect();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(lines.as_bytes()).unwrap();
    let mut gzipped = encoder.finish().unwrap();
    gzipped.truncate(gzipped.len() / 2);
    fs::write(dir.join("warc.paths.gz"), gzipped).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cc-extract"))
        .current_dir(&dir)
        .args(["warc.paths.gz", "--formats", "warc", "--limit", "1"])
        .args(["--kvrocks", &no_store(&dir)])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "cc-extract should fail:\n{stderr}"
    );
    // The startup line names the file too: match the error itself.
    assert!(
        stderr.contains("cannot read 'warc.paths.gz'"),
        "the message should name the paths file:\n{stderr}"
    );
}

/// Only WARC serves `inline-favicon`, so asking for it plans WARC
/// even on CC-MAIN, and `onion` reads that WARC instead of WAT + WET. The
/// WAT and WET Archives are not in `download/`: fetching them would fail
/// the run.
///
/// The PNG on two pages is one Artifact, keyed by the SHA-256 of its bytes,
/// with two Sightings.
#[test]
fn inline_favicon_plans_warc_and_onion_rides_along() {
    let Some(store) = TestStore::take("inline_favicon_plans_warc_and_onion_rides_along") else {
        return;
    };
    let dir = workspace(
        "inline_favicon_plans_warc_and_onion_rides_along",
        &[(WARC_NAME, inline_favicon_warc_archive())],
    );

    let stderr = crawl(&store, &dir, &["-e", "onion,inline-favicon"]);

    assert!(
        stderr.contains(&format!(
            "{SHARD}: extracting onion,inline-favicon from warc\n"
        )),
        "the Plan should be WARC:\n{stderr}"
    );
    let (findings, processed) = store.state();
    assert_eq!(
        processed,
        [format!("{SHARD} inline-favicon"), format!("{SHARD} onion")]
    );
    let [onions, favicons, inline_favicons]: [Findings; 3] = findings.try_into().unwrap();
    assert_eq!(
        onions,
        Findings::Sightings(HashMap::from([(
            TEXT_ONION.to_string(),
            vec![Sighting {
                page_url: PAGE.to_string(),
                date: DATE.to_string(),
                shard: Shard::from_archive_name(SHARD),
            }]
        )]))
    );
    assert!(favicons.is_empty());
    let sighting = |page_url: &str, date: &str| Sighting {
        page_url: page_url.to_string(),
        date: date.to_string(),
        shard: Shard::from_archive_name(SHARD),
    };
    assert_eq!(
        inline_favicons,
        normalized(Findings::InlineFavicons(HashMap::from([(
            PNG_SHA256.to_string(),
            InlineFavicon {
                mmh3: PNG_MMH3,
                media_type: "image/png".to_string(),
                data: String::new(),
                sightings: vec![sighting(PAGE, DATE), sighting(OTHER_PAGE, OTHER_DATE)],
            }
        )])))
    );

    // The keys themselves, so the layout consumers read is pinned too.
    let strings = |pairs: &[(&str, &str)]| -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(field, value)| (field.to_string(), value.to_string()))
            .collect()
    };
    assert_eq!(
        store.fields(&format!("image:{PNG_SHA256}")),
        strings(&[("media_type", "image/png"), ("mmh3", &PNG_MMH3.to_string())])
    );
    assert_eq!(
        store.members(&format!("inline-favicon:{PNG_SHA256}")),
        BTreeSet::from([page_id(PAGE), page_id(OTHER_PAGE)])
    );
    let id = page_id(PAGE);
    assert_eq!(
        store.fields(&format!("page:{id}")),
        strings(&[("page_url", PAGE), ("date", DATE), ("shard", SHARD)])
    );
    assert_eq!(
        store.members(&format!("page:{id}:inline-favicon")),
        BTreeSet::from([PNG_SHA256.to_string()])
    );
    assert_eq!(
        store.members(&format!("page:{id}:onion")),
        BTreeSet::from([TEXT_ONION.to_string()])
    );
    assert_eq!(
        store.members("artifacts:inline-favicon"),
        BTreeSet::from([PNG_SHA256.to_string()])
    );
}
