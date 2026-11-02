// Tests of the results store, through its in-memory implementation.
//
// After each Shard, the crawl writes each done kind's Findings to the store,
// then marks the (Shard, kind) pair done (`save_then_mark`); at start-up it
// reads the done pairs back (`load_processed`). `MemoryStore` behaves as
// kvrocks does for the few commands the store uses, so these tests need no
// server; `crawl_cli.rs` runs the same code against a real kvrocks.

// Each test crate compiles its own copy of `common` and uses only part of
// it; `allow` silences the dead-code warnings for the rest.
#[allow(dead_code)]
mod common;

use std::collections::{HashMap, HashSet};

use cc_extract::store::{
    MemoryStore, Store, Write, artifact_count, load_processed, save_then_mark,
};
use cc_extract::{ArtifactKind, Findings, InlineFavicon, Shard, Sighting};
use common::{findings_in, normalized};

/// The `n`th Shard of a made-up Crawl.
fn shard(n: u32) -> Shard {
    Shard::from_archive_name(&format!("CC-MAIN-20250101000000-20250101010101-{n:05}"))
}

/// A Sighting on `page_url` in Shard `n`.
fn on(page_url: &str, n: u32) -> Sighting {
    Sighting {
        page_url: page_url.to_string(),
        date: format!("2025-01-01T00:00:{n:02}Z"),
        shard: shard(n),
    }
}

/// `Findings::Sightings` from `(artifact, sightings)` pairs.
fn sightings(entries: &[(&str, Vec<Sighting>)]) -> Findings {
    Findings::Sightings(
        entries
            .iter()
            .map(|(artifact, sightings)| (artifact.to_string(), sightings.clone()))
            .collect(),
    )
}

/// The hashes of a 1×1 PNG: SHA-256, SHA-1 and MD5 by `shasum` and `md5`,
/// Shodan's by Python's `mmh3.hash(codecs.encode(png, "base64"))`.
const IMAGE: &str = "49e1dad481e94dfab7c9573a9a81d56aa2ca629fe15a3f7a910aa4f47601c00d";
const IMAGE_SHA1: &str = "7679eec1d792d130b56cc3a3d9c55a750600ac64";
const IMAGE_MD5: &str = "340680474585d738bda590f1675a0f46";
const IMAGE_MMH3: i32 = 1_932_519_735;

/// The PNG, declared as `media_type`, seen on `sightings`. Its bytes are
/// left out: the store never keeps them.
fn png(media_type: &str, sightings: Vec<Sighting>) -> InlineFavicon {
    InlineFavicon {
        mmh3: IMAGE_MMH3,
        sha1: IMAGE_SHA1.to_string(),
        md5: IMAGE_MD5.to_string(),
        media_type: media_type.to_string(),
        bytes: Vec::new(),
        sightings,
    }
}

/// `Findings::InlineFavicons` holding the PNG, declared as `media_type`.
fn inline_favicon(media_type: &str, sightings: Vec<Sighting>) -> Findings {
    Findings::InlineFavicons(HashMap::from([(
        IMAGE.to_string(),
        png(media_type, sightings),
    )]))
}

/// A Shard, and what each kind found in it.
type ShardFindings = (Shard, Vec<(ArtifactKind, Findings)>);

/// What each kind finds in Shards 0 and 1 of the made-up Crawl: Artifacts
/// seen in both, pages seen in both, a page with several Artifacts.
fn two_shards() -> [ShardFindings; 2] {
    let a = "https://a.example/";
    let b = "https://b.example/";
    [
        (
            shard(0),
            vec![
                (
                    ArtifactKind::Onion,
                    sightings(&[
                        ("aaaaaaaaaaaaaaaa.onion", vec![on(a, 0)]),
                        ("bbbbbbbbbbbbbbbb.onion", vec![on(a, 0), on(b, 0)]),
                    ]),
                ),
                (
                    ArtifactKind::Favicon,
                    sightings(&[("https://a.example/icon.png", vec![on(a, 0)])]),
                ),
                (
                    ArtifactKind::InlineFavicon,
                    inline_favicon("image/png", vec![on(a, 0)]),
                ),
            ],
        ),
        (
            shard(1),
            vec![
                (
                    ArtifactKind::Onion,
                    sightings(&[
                        // The same page, crawled again in another Shard: a
                        // second Sighting.
                        ("aaaaaaaaaaaaaaaa.onion", vec![on(a, 1)]),
                        ("cccccccccccccccc.onion", vec![on(b, 1)]),
                    ]),
                ),
                (
                    ArtifactKind::Favicon,
                    sightings(&[
                        ("https://a.example/icon.png", vec![on(a, 1)]),
                        ("https://b.example/favicon.ico", vec![on(b, 1)]),
                    ]),
                ),
                (
                    ArtifactKind::InlineFavicon,
                    // The same image, declared with another media type: the
                    // first one written is kept.
                    inline_favicon("image/x-icon", vec![on(b, 1)]),
                ),
            ],
        ),
    ]
}

/// Each kind's Findings over both Shards, merged as the crawl merged its
/// results before the store.
fn merged(shards: &[ShardFindings], kind: ArtifactKind) -> Findings {
    let mut all = Findings::empty(kind);
    for (_, found) in shards {
        for (found_kind, findings) in found {
            if *found_kind == kind {
                all.merge(findings.clone());
            }
        }
    }
    all
}

/// Write every kind's Findings of every Shard in `shards`, each followed by
/// its done mark.
async fn write_all(store: &mut MemoryStore, shards: &[ShardFindings]) {
    for (shard, found) in shards {
        for (kind, findings) in found {
            save_then_mark(store, *kind, findings, shard, &mut 0)
                .await
                .unwrap();
        }
    }
}

#[tokio::test]
async fn sightings_written_over_several_shards_read_back_as_their_merge() {
    let shards = two_shards();
    let mut store = MemoryStore::new();

    write_all(&mut store, &shards).await;

    for &kind in ArtifactKind::all() {
        assert_eq!(
            findings_in(&mut store, kind).await,
            normalized(merged(&shards, kind)),
            "{kind}"
        );
    }
    let every_pair: HashSet<(Shard, ArtifactKind)> = [shard(0), shard(1)]
        .into_iter()
        .flat_map(|shard| {
            ArtifactKind::all()
                .iter()
                .map(move |&kind| (shard.clone(), kind))
        })
        .collect();
    assert_eq!(load_processed(&mut store).await.unwrap(), every_pair);
}

/// A Shard done again (after a kill between its writes and its mark) writes
/// the same members and fields: the store is left as it was, and no
/// Artifact counts as new.
#[tokio::test]
async fn writing_the_same_shard_twice_changes_nothing() {
    let shards = two_shards();
    let mut store = MemoryStore::new();
    write_all(&mut store, &shards).await;
    let before = store.clone();

    for (kind, findings) in &shards[1].1 {
        let mut new_artifacts = 0;
        save_then_mark(
            &mut store,
            *kind,
            findings,
            &shards[1].0,
            &mut new_artifacts,
        )
        .await
        .unwrap();
        assert_eq!(new_artifacts, 0, "{kind}");
    }

    assert_eq!(store, before);
}

/// `pairs` as a hash's fields, as `Store::fields` reads them.
fn fields(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(field, value)| (field.to_string(), value.to_string()))
        .collect()
}

/// An inline favicon is described by its media type and hashes, not its
/// bytes, and can be found from each hash: the index sets of mmh3, SHA-1
/// and MD5 hold its SHA-256.
#[tokio::test]
async fn an_inline_favicon_is_found_from_each_of_its_hashes() {
    let mut store = MemoryStore::new();
    let findings = inline_favicon("image/png", vec![on("https://a.example/", 0)]);

    save_then_mark(
        &mut store,
        ArtifactKind::InlineFavicon,
        &findings,
        &shard(0),
        &mut 0,
    )
    .await
    .unwrap();

    assert_eq!(
        store.fields(&format!("image:{IMAGE}")).await.unwrap(),
        fields(&[
            ("media_type", "image/png"),
            ("mmh3", "1932519735"),
            ("sha1", IMAGE_SHA1),
            ("md5", IMAGE_MD5),
        ])
    );
    for index in [
        "mmh3:1932519735".to_string(),
        format!("sha1:{IMAGE_SHA1}"),
        format!("md5:{IMAGE_MD5}"),
    ] {
        assert_eq!(store.members(&index).await.unwrap(), [IMAGE], "{index}");
    }
}

/// Shodan's hash is 32 bits: two different images can share one, and its
/// index then lists both, the second written adding to the first.
#[tokio::test]
async fn images_sharing_an_mmh3_both_stay_in_its_index() {
    let other = "0f".repeat(32);
    let other_image = InlineFavicon {
        sha1: "0f".repeat(20),
        md5: "0f".repeat(16),
        ..png("image/png", vec![on("https://b.example/", 1)])
    };
    let mut store = MemoryStore::new();

    save_then_mark(
        &mut store,
        ArtifactKind::InlineFavicon,
        &inline_favicon("image/png", vec![on("https://a.example/", 0)]),
        &shard(0),
        &mut 0,
    )
    .await
    .unwrap();
    save_then_mark(
        &mut store,
        ArtifactKind::InlineFavicon,
        &Findings::InlineFavicons(HashMap::from([(other.clone(), other_image)])),
        &shard(1),
        &mut 0,
    )
    .await
    .unwrap();

    let mut images = store.members("mmh3:1932519735").await.unwrap();
    images.sort();
    assert_eq!(images, [other, IMAGE.to_string()]);
}

/// Only the Sightings of `shard` among `findings`.
fn only_in(shard: &Shard, findings: Findings) -> Findings {
    let keep = |sightings: &mut Vec<Sighting>| sightings.retain(|s| s.shard == *shard);
    let mut findings = findings;
    match &mut findings {
        Findings::Sightings(map) => {
            map.values_mut().for_each(keep);
            map.retain(|_, sightings| !sightings.is_empty());
        }
        Findings::InlineFavicons(map) => {
            map.values_mut()
                .for_each(|favicon| keep(&mut favicon.sightings));
            map.retain(|_, favicon| !favicon.sightings.is_empty());
        }
    }
    findings
}

/// A write failing in the middle of a pair's Sightings (a lost connection)
/// leaves that pair unmarked, so the next run does it again, and the pairs
/// written before it as they were. Done again, the pair is complete.
#[tokio::test]
async fn a_failing_write_leaves_the_pair_unmarked() {
    let [first, second] = two_shards();
    let mut store = MemoryStore::new();
    write_all(&mut store, std::slice::from_ref(&first)).await;
    let (second_shard, second_found) = &second;
    let (kind, findings) = &second_found[1];
    assert_eq!(*kind, ArtifactKind::Favicon);

    // A few of the pair's writes go through, then the rest fail.
    store.fail_after(3);
    let saved = save_then_mark(&mut store, *kind, findings, second_shard, &mut 0).await;

    assert!(saved.is_err());
    let processed = load_processed(&mut store).await.unwrap();
    assert!(!processed.contains(&(second_shard.clone(), *kind)));
    for (kind, findings) in &first.1 {
        assert!(processed.contains(&(first.0.clone(), *kind)));
        assert_eq!(
            only_in(&first.0, findings_in(&mut store, *kind).await),
            normalized(findings.clone()),
            "{kind}"
        );
    }

    store.stop_failing();
    save_then_mark(&mut store, *kind, findings, second_shard, &mut 0)
        .await
        .unwrap();
    assert!(
        load_processed(&mut store)
            .await
            .unwrap()
            .contains(&(second_shard.clone(), *kind))
    );
    let both = [first, second.clone()];
    assert_eq!(
        findings_in(&mut store, *kind).await,
        normalized(merged(&both, *kind))
    );
}

/// A `processed` member without a kind this version knows marks nothing:
/// scheduling does those Shards again.
#[tokio::test]
async fn done_marks_without_a_known_kind_are_ignored() {
    let mut store = MemoryStore::new();
    let marks = [
        format!("{} onion", shard(0)),
        format!("{} not-a-kind", shard(1)),
        // No kind at all.
        shard(2).to_string(),
    ];
    let writes: Vec<Write> = marks
        .into_iter()
        .map(|member| Write::SetAdd {
            key: "processed".to_string(),
            member,
        })
        .collect();
    store.write(&writes).await.unwrap();

    assert_eq!(
        load_processed(&mut store).await.unwrap(),
        HashSet::from([(shard(0), ArtifactKind::Onion)])
    );
}

/// The number of Artifacts new to the store, which the crawl's summary
/// reports, and how many it holds in all.
#[tokio::test]
async fn new_artifacts_are_those_the_store_did_not_hold() {
    let [first, second] = two_shards();
    let mut store = MemoryStore::new();
    let first_new = write_onions(&mut store, &first).await;
    let second_new = write_onions(&mut store, &second).await;

    // `a` and `b` in the first Shard; only `c` in the second, `a` again.
    assert_eq!(first_new, 2);
    assert_eq!(second_new, 1);
    let total = artifact_count(&mut store, ArtifactKind::Onion).await;
    assert_eq!(total.unwrap(), 3);
}

/// Write the onions `shard_findings` lists first; returns how many were new
/// to `store`.
async fn write_onions(store: &mut MemoryStore, (shard, found): &ShardFindings) -> usize {
    let (kind, onions) = &found[0];
    assert_eq!(*kind, ArtifactKind::Onion);
    let mut new_artifacts = 0;
    save_then_mark(store, *kind, onions, shard, &mut new_artifacts)
        .await
        .unwrap();
    new_artifacts
}

/// Artifacts added before a write fails are counted as new: in the store
/// already, they won't be new to the run that does the pair again.
#[tokio::test]
async fn new_artifacts_written_before_a_failure_are_counted() {
    // Enough onions, each on a page of its own, to fill several batches.
    let onions: Vec<(String, Vec<Sighting>)> = (0..5_000)
        .map(|n| {
            (
                format!("{n:016}.onion"),
                vec![on(&format!("https://{n}.example/"), 0)],
            )
        })
        .collect();
    let findings = Findings::Sightings(onions.into_iter().collect());
    let mut store = MemoryStore::new();
    // About half of the writes go through.
    store.fail_after(15_000);

    let mut new_artifacts = 0;
    let saved = save_then_mark(
        &mut store,
        ArtifactKind::Onion,
        &findings,
        &shard(0),
        &mut new_artifacts,
    )
    .await;

    assert!(saved.is_err());
    assert!(new_artifacts > 0);
    let in_store = artifact_count(&mut store, ArtifactKind::Onion)
        .await
        .unwrap();
    assert!(new_artifacts <= in_store, "{new_artifacts} > {in_store}");
}
