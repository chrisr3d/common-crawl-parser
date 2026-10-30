// Tests for downloading an Archive and saving it to `download/`.
//
// The crawl takes a file at an Archive's name in `download/` as that
// Archive, complete: it parses it instead of downloading it again. So the
// bytes may reach that name only once all of them arrived. The first tests
// hand `save_archive` the body as a stream of chunks, the way the HTTP
// client delivers it, so no network is needed.
//
// A download must also end: one whose server stops sending data fails after
// the client's read timeout, while a slow one that keeps receiving data is
// never cut. Those tests download from a server of their own on 127.0.0.1.

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use cc_extract::{HttpClient, download_to, download_to_memory, save_archive};
use futures::stream::{self, StreamExt};
use tokio::time::timeout;

const ARCHIVE_NAME: &str = "CC-MAIN-20250101000000-20250101010101-00000.warc.wat.gz";

/// The read timeout of the tests' HTTP client: short, so that a stalled
/// download fails quickly.
const READ_TIMEOUT: Duration = Duration::from_millis(500);

/// How much longer than expected a download may take before its test
/// counts it as hung, rather than waiting for it forever.
const MARGIN: Duration = Duration::from_secs(2);

/// A slow download's body comes in `SLOW_CHUNKS` chunks, one every
/// `SLOW_GAP`: each wait is shorter than `READ_TIMEOUT`, all of them
/// together longer.
const SLOW_CHUNKS: u32 = 8;
const SLOW_GAP: Duration = Duration::from_millis(100);

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

/// Start a server on a free port of 127.0.0.1, on a thread of its own, that
/// reads one HTTP request and answers it with `respond`. Returns the URL of
/// the Archive to request from it.
fn serve_once(respond: fn(TcpStream)) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/{}", listener.local_addr().unwrap(), ARCHIVE_NAME);
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        // A GET request has no body: it ends with an empty line, `\r\n`.
        let mut request = BufReader::new(&stream);
        let mut line = String::new();
        while request.read_line(&mut line).unwrap_or(0) > 2 {
            line.clear();
        }
        respond(stream);
    });
    url
}

/// Announce 1,000 bytes, send 500, then send nothing more, keeping the
/// connection open until the client closes it.
fn stall(mut stream: TcpStream) {
    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n");
    let _ = stream.write_all(&[b'x'; 500]);
    // Blocks until the client closes the connection (the read returns 0).
    let _ = stream.read(&mut [0; 1]);
}

/// The chunks of a slow download's body.
fn slow_chunks() -> Vec<Vec<u8>> {
    (0..SLOW_CHUNKS)
        .map(|index| format!("chunk {index}\n").into_bytes())
        .collect()
}

/// Announce the length of `slow_chunks`, then send them one at a time,
/// each `SLOW_GAP` after the one before.
fn trickle(mut stream: TcpStream) {
    let chunks = slow_chunks();
    let length: usize = chunks.iter().map(Vec::len).sum();
    // Send each chunk at once, rather than holding a small one back until
    // the previous is acknowledged (Nagle's algorithm).
    let _ = stream.set_nodelay(true);
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n"
    );
    for chunk in chunks {
        thread::sleep(SLOW_GAP);
        let _ = stream.write_all(&chunk);
    }
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

#[tokio::test]
async fn stalled_download_fails_and_leaves_nothing() {
    let dir = download_dir("stalled_download_fails_and_leaves_nothing");
    let url = serve_once(stall);
    let client = HttpClient::new(READ_TIMEOUT).unwrap();

    let local_path = dir.join(ARCHIVE_NAME);
    let download = download_to(&client, &url, &local_path);
    let saved = timeout(READ_TIMEOUT + MARGIN, download)
        .await
        .expect("the stalled download hung");

    assert_eq!(saved.unwrap_err().to_string(), "no data received for 0.5 s");
    assert!(file_names(&dir).is_empty(), "{:?}", file_names(&dir));
}

#[tokio::test]
async fn stalled_download_to_memory_fails() {
    let url = serve_once(stall);
    let client = HttpClient::new(READ_TIMEOUT).unwrap();

    let downloaded = timeout(READ_TIMEOUT + MARGIN, download_to_memory(&client, &url))
        .await
        .expect("the stalled download hung");

    assert_eq!(
        downloaded.unwrap_err().to_string(),
        "no data received for 0.5 s"
    );
}

#[tokio::test]
async fn slow_download_still_receiving_data_completes() {
    let dir = download_dir("slow_download_still_receiving_data_completes");
    let url = serve_once(trickle);
    let client = HttpClient::new(READ_TIMEOUT).unwrap();

    let started = Instant::now();
    let local_path = dir.join(ARCHIVE_NAME);
    let download = download_to(&client, &url, &local_path);
    timeout(SLOW_GAP * SLOW_CHUNKS + MARGIN, download)
        .await
        .expect("the slow download hung")
        .unwrap();

    // Longer than the read timeout in all, yet not cut.
    assert!(started.elapsed() > READ_TIMEOUT);
    assert_eq!(fs::read(&local_path).unwrap(), slow_chunks().concat());
    assert_eq!(file_names(&dir), [ARCHIVE_NAME]);
}

#[tokio::test]
async fn slow_download_to_memory_still_receiving_data_completes() {
    let url = serve_once(trickle);
    let client = HttpClient::new(READ_TIMEOUT).unwrap();

    let started = Instant::now();
    let downloaded = timeout(
        SLOW_GAP * SLOW_CHUNKS + MARGIN,
        download_to_memory(&client, &url),
    )
    .await
    .expect("the slow download hung")
    .unwrap();

    // Longer than the read timeout in all, yet not cut.
    assert!(started.elapsed() > READ_TIMEOUT);
    assert_eq!(downloaded, slow_chunks().concat());
}
