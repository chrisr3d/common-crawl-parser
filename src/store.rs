// The results store — where Sightings and done marks are written
//
// After each Shard, every kind whose Archives all parsed has its Findings
// written to a kvrocks store (the Redis protocol, kept on disk), then its
// (Shard, kind) pair marked done. At start-up the done pairs are read back
// to schedule the run; no results are loaded into RAM.
//
// ## Keys
//
// Kinds are named as on the command line (`onion`, `favicon`,
// `inline-favicon`):
//
//   page:<id>             hash  `page_url`, `date`, `shard` of one Page
//   <kind>:<artifact>     set   ids of the Pages the Artifact was seen on
//   page:<id>:<kind>      set   the Page's Artifacts of that kind
//   artifacts:<kind>      set   every Artifact of the kind
//   image:<sha256>        hash  `media_type`, `mmh3`, `sha1`, `md5` of an
//                               inline favicon
//   mmh3:<value>,         set   SHA-256s of the inline favicons having
//   sha1:<hex>, md5:<hex>       that value
//   processed             set   `<shard> <kind>`, one per done pair
//   failures              set   `<archive> <run>`, one per counted failure
//   failures:<archive>    hash  the error message of each run (`<run>`)
//                               that counted a failure on the Archive
//
// `<artifact>` is an onion address, a favicon URL, or the SHA-256 of an
// inline favicon. One Sighting is one Page in an Artifact's set: a Page is
// one URL in one Shard, so Sightings are deduplicated on `(page_url, shard)`
// as before, by the set itself.
//
// An image's bytes are never written: `--save-images` puts them on disk.
//
// `<archive>` is an Archive's file name, `<run>` a `RunId`. A failure is
// counted only when both keys hold it (see `load_failures`).
//
// ## Only adding, never replacing
//
// Every write is a `SADD` (add a member to a set) or an `HSETNX` (set a
// hash field only if it is absent). Neither can remove or change what is
// there, so writing the same Findings twice changes nothing, and the first
// `date` or `media_type` written is the one kept.
//
// ## One seam, two stores
//
// The functions below the two stores (`save_then_mark`, `load_processed`,
// `artifact_count`, `record_failure`, `load_failures`) decide what is
// written and in which order. They reach
// the store only through the `Store` trait: the crawl passes them a
// `KvrocksStore`, the tests a `MemoryStore`, so the tests run the code the
// crawl runs without a server.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::process;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use redis::aio::MultiplexedConnection;
use redis::{
    AsyncConnectionConfig, ConnectionAddr, FromRedisValue, IntoConnectionInfo, RedisConnectionInfo,
};
use url::{Host, Url};

use crate::artifact::{ArtifactKind, Findings, Shard, Sighting};
use crate::inline_favicon::{InlineFavicon, sha256_hex};

/// What a store operation returns: `Box<dyn Error + Send + Sync>` holds a
/// connection error from kvrocks as well as `MemoryStore`'s refusals.
pub type StoreResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

// ---------------------------------------------------------------------------
// The Store trait
// ---------------------------------------------------------------------------

/// One write to the store. Both only add (see the module comment), so
/// applying one twice changes nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Write {
    /// `SADD key member`: add `member` to the set at `key`.
    SetAdd { key: String, member: String },
    /// `HSETNX key field value`: set `field` of the hash at `key`, unless it
    /// is set already.
    HashSetIfAbsent {
        key: String,
        field: String,
        value: String,
    },
}

/// What the crawl needs of a Redis-protocol store: a few commands, so a
/// test double can stand in for kvrocks.
///
/// ## Async methods in a trait
///
/// Writing to kvrocks waits on a socket, so the methods are async. A trait
/// method can be declared `async fn`, but then whoever calls it through a
/// generic `S: Store` can't know whether the future it returns is `Send`
/// (safe to move to another thread), which `tokio::spawn` requires. Writing
/// the return type out as `impl Future<Output = ..> + Send` makes it part
/// of the contract. Implementations still write `async fn`: the compiler
/// checks that each one's future is `Send`.
pub trait Store {
    /// Apply `writes` in order, and say for each one whether it changed the
    /// store (a member added, a field set). If one fails, the call fails,
    /// and any of the others, before or after it, may have been applied.
    fn write(&mut self, writes: &[Write]) -> impl Future<Output = StoreResult<Vec<bool>>> + Send;

    /// The members of the set at `key` (`SMEMBERS`); none if there is no set.
    fn members(&mut self, key: &str) -> impl Future<Output = StoreResult<Vec<String>>> + Send;

    /// The fields of the hash at `key` (`HGETALL`); none if there is no hash.
    fn fields(
        &mut self,
        key: &str,
    ) -> impl Future<Output = StoreResult<HashMap<String, String>>> + Send;

    /// How many members the set at `key` has (`SCARD`).
    fn count(&mut self, key: &str) -> impl Future<Output = StoreResult<usize>> + Send;

    /// The fields of the hash at each of `keys`, in the same order: one
    /// `HGETALL` each, sent together in one round trip.
    fn fields_of_each(
        &mut self,
        keys: &[String],
    ) -> impl Future<Output = StoreResult<Vec<HashMap<String, String>>>> + Send;
}

// ---------------------------------------------------------------------------
// The in-memory store
// ---------------------------------------------------------------------------

/// A store held in memory, for tests: sets and hashes in maps, written as
/// kvrocks writes them.
///
/// It can be told to fail (`fail_after`), like a connection lost in the
/// middle of a Shard's writes. `PartialEq` compares every key, so a test
/// can check that writing something again left the store as it was.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemoryStore {
    sets: BTreeMap<String, BTreeSet<String>>,
    hashes: BTreeMap<String, BTreeMap<String, String>>,
    /// How many more writes are accepted; `None`: all of them.
    writes_left: Option<usize>,
}

impl MemoryStore {
    /// An empty store, accepting every write.
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept `writes` more writes, then fail every one after them.
    pub fn fail_after(&mut self, writes: usize) {
        self.writes_left = Some(writes);
    }

    /// Accept every write again.
    pub fn stop_failing(&mut self) {
        self.writes_left = None;
    }

    /// Remove the set or hash at `key`, as `DEL` does: what a user does by
    /// hand, such as deleting failure records to retry an Archive.
    pub fn delete(&mut self, key: &str) {
        self.sets.remove(key);
        self.hashes.remove(key);
    }
}

impl Store for MemoryStore {
    async fn write(&mut self, writes: &[Write]) -> StoreResult<Vec<bool>> {
        let mut changed = Vec::with_capacity(writes.len());
        for write in writes {
            if let Some(left) = &mut self.writes_left {
                if *left == 0 {
                    return Err("the in-memory store was told to fail".into());
                }
                *left -= 1;
            }
            changed.push(match write {
                // `insert` returns whether the value was new: what `SADD`
                // replies.
                Write::SetAdd { key, member } => self
                    .sets
                    .entry(key.clone())
                    .or_default()
                    .insert(member.clone()),
                Write::HashSetIfAbsent { key, field, value } => {
                    let hash = self.hashes.entry(key.clone()).or_default();
                    let absent = !hash.contains_key(field);
                    if absent {
                        hash.insert(field.clone(), value.clone());
                    }
                    absent
                }
            });
        }
        Ok(changed)
    }

    async fn members(&mut self, key: &str) -> StoreResult<Vec<String>> {
        let set = self.sets.get(key);
        Ok(set.into_iter().flatten().cloned().collect())
    }

    async fn fields(&mut self, key: &str) -> StoreResult<HashMap<String, String>> {
        let hash = self.hashes.get(key);
        Ok(hash
            .into_iter()
            .flatten()
            .map(|(f, v)| (f.clone(), v.clone()))
            .collect())
    }

    async fn count(&mut self, key: &str) -> StoreResult<usize> {
        Ok(self.sets.get(key).map_or(0, BTreeSet::len))
    }

    async fn fields_of_each(
        &mut self,
        keys: &[String],
    ) -> StoreResult<Vec<HashMap<String, String>>> {
        let mut all = Vec::with_capacity(keys.len());
        for key in keys {
            all.push(self.fields(key).await?);
        }
        Ok(all)
    }
}

// ---------------------------------------------------------------------------
// The kvrocks store
// ---------------------------------------------------------------------------

/// How long connecting to the store may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the store may take to answer one command or batch. A store
/// that stops answering fails the write, and its pair is left undone,
/// rather than holding the run (and its downloads) forever. `redis` waits
/// 500 ms by default: too short for a batch of `BATCH_SIZE` writes to a
/// store busy writing to disk.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// A kvrocks store, reached through the `redis` crate.
///
/// ## One connection, shared
///
/// A `MultiplexedConnection` sends the commands of every clone of it over
/// one connection, a task on the tokio runtime matching each reply to its
/// command. The crawl writes from one loop, so one is enough; cloning it
/// would not open another.
///
/// ## Opened again when lost
///
/// A `MultiplexedConnection` the server has dropped (a network fault, the
/// store restarted) fails every command sent on it from then on. A call
/// failing that way forgets it (`None`), and the next call opens a new
/// one, from the `Client`, which keeps the address and the password: one
/// lost connection fails the call that finds it gone, not the rest of the
/// run. A store that stays down costs each call one attempt to connect,
/// within `CONNECT_TIMEOUT`.
pub struct KvrocksStore {
    client: redis::Client,
    connection: Option<MultiplexedConnection>,
}

impl KvrocksStore {
    /// Connect to the store at `address`, sending `password` with `AUTH`
    /// if given, and check that it answers (`PING`).
    pub async fn connect(address: &StoreAddress, password: Option<String>) -> StoreResult<Self> {
        let client = address.client(password)?;
        let mut connection = open_connection(&client).await?;
        redis::cmd("PING")
            .query_async::<()>(&mut connection)
            .await?;
        Ok(KvrocksStore {
            client,
            connection: Some(connection),
        })
    }

    /// The connection, a new one if the last was lost.
    ///
    /// `take` moves the connection out of the `Option`, leaving `None`;
    /// `insert` puts one back and returns a reference to it.
    async fn connection(&mut self) -> redis::RedisResult<&mut MultiplexedConnection> {
        let connection = match self.connection.take() {
            Some(connection) => connection,
            None => open_connection(&self.client).await?,
        };
        Ok(self.connection.insert(connection))
    }

    /// `result`, the connection forgotten if the error says it is lost:
    /// the next call opens a new one. A timeout, or a command the store
    /// refuses, keeps it.
    fn forget_if_lost<T>(&mut self, result: redis::RedisResult<T>) -> StoreResult<T> {
        if let Err(err) = &result
            && err.is_unrecoverable_error()
        {
            self.connection = None;
        }
        Ok(result?)
    }
}

/// A new connection from `client`, with the store's timeouts.
async fn open_connection(client: &redis::Client) -> redis::RedisResult<MultiplexedConnection> {
    let config = AsyncConnectionConfig::new()
        .set_connection_timeout(Some(CONNECT_TIMEOUT))
        .set_response_timeout(Some(RESPONSE_TIMEOUT));
    client
        .get_multiplexed_async_connection_with_config(&config)
        .await
}

impl Store for KvrocksStore {
    async fn write(&mut self, writes: &[Write]) -> StoreResult<Vec<bool>> {
        // A pipeline: every command queued, sent at once, the replies read
        // back in the same order. Without `atomic()`, no `MULTI` / `EXEC`
        // around them. A command the store refuses fails the whole call.
        let mut pipe = redis::pipe();
        for write in writes {
            match write {
                Write::SetAdd { key, member } => pipe.cmd("SADD").arg(key).arg(member),
                Write::HashSetIfAbsent { key, field, value } => {
                    pipe.cmd("HSETNX").arg(key).arg(field).arg(value)
                }
            };
        }
        // Both commands reply 1 when they changed something, 0 otherwise;
        // `redis` reads such an integer as a `bool`.
        let result = pipe.query_async(self.connection().await?).await;
        self.forget_if_lost(result)
    }

    async fn members(&mut self, key: &str) -> StoreResult<Vec<String>> {
        self.read("SMEMBERS", key).await
    }

    async fn fields(&mut self, key: &str) -> StoreResult<HashMap<String, String>> {
        self.read("HGETALL", key).await
    }

    async fn count(&mut self, key: &str) -> StoreResult<usize> {
        self.read("SCARD", key).await
    }

    async fn fields_of_each(
        &mut self,
        keys: &[String],
    ) -> StoreResult<Vec<HashMap<String, String>>> {
        // A pipeline, as `write` sends: the replies come back in the order
        // of the keys. One with no command sends nothing.
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let mut pipe = redis::pipe();
        for key in keys {
            pipe.cmd("HGETALL").arg(key);
        }
        let result = pipe.query_async(self.connection().await?).await;
        self.forget_if_lost(result)
    }
}

impl KvrocksStore {
    /// The reply to `command key`, read as a `T`.
    ///
    /// `FromRedisValue` is the `redis` crate's trait for types a reply can
    /// be read as: the caller's return type picks the conversion, a list of
    /// strings for `SMEMBERS`, a map for `HGETALL`, a number for `SCARD`.
    async fn read<T: FromRedisValue>(&mut self, command: &str, key: &str) -> StoreResult<T> {
        let result = redis::cmd(command)
            .arg(key)
            .query_async(self.connection().await?)
            .await;
        self.forget_if_lost(result)
    }
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// The set of done pairs.
const PROCESSED_KEY: &str = "processed";

/// The id of the Page `page_url` in `shard`: the first 16 bytes of the
/// SHA-256 of `"<shard> <page_url>"`, in lowercase hex.
///
/// Computed from the Page alone, so a Shard written again gives the same
/// ids, and every set lists 32 characters per Page instead of its URL.
fn page_id(shard: &Shard, page_url: &str) -> String {
    let mut id = sha256_hex(format!("{shard} {page_url}").as_bytes());
    // Two hex digits per byte.
    id.truncate(32);
    id
}

/// The set listing every Artifact of `kind`.
fn artifacts_key(kind: ArtifactKind) -> String {
    format!("artifacts:{kind}")
}

// ---------------------------------------------------------------------------
// Writing one Shard
// ---------------------------------------------------------------------------

/// How many writes go to the store in one round trip.
///
/// Sent one by one, each write would wait for its reply before the next
/// leaves: one Shard's favicons are about 200,000 writes. *Pipelining*
/// sends a whole batch, then reads the replies, which come back in the
/// same order. The batch bounds how many writes are held in memory at once.
const BATCH_SIZE: usize = 10_000;

/// One Artifact of some Findings, whichever kind: what it is, its
/// Sightings, and for an inline favicon its description.
struct FoundArtifact<'a> {
    artifact: &'a str,
    sightings: &'a [Sighting],
    image: Option<&'a InlineFavicon>,
}

/// Every Artifact in `findings`.
fn found_artifacts(findings: &Findings) -> Vec<FoundArtifact<'_>> {
    match findings {
        Findings::Sightings(map) => map
            .iter()
            .map(|(artifact, sightings)| FoundArtifact {
                artifact,
                sightings,
                image: None,
            })
            .collect(),
        Findings::InlineFavicons(map) => map
            .iter()
            .map(|(artifact, favicon)| FoundArtifact {
                artifact,
                sightings: &favicon.sightings,
                image: Some(favicon),
            })
            .collect(),
    }
}

/// Add to `batch` one `HSETNX` per field of the hash at `key`.
fn push_fields<const N: usize>(
    batch: &mut Vec<Write>,
    key: &str,
    fields: [(&'static str, String); N],
) {
    for (field, value) in fields {
        batch.push(Write::HashSetIfAbsent {
            key: key.to_string(),
            field: field.to_string(),
            value,
        });
    }
}

/// Add to `batch` the writes recording `found`, an Artifact of `kind`.
/// `pages_written` holds the ids of the Pages already written in this
/// batch's Shard, whose fields need no second write.
///
/// The Artifact joins `artifacts:<kind>` last, after the sets it leads to:
/// someone reading the store while the crawl runs finds the Pages of every
/// Artifact listed there.
fn push_writes(
    kind: ArtifactKind,
    found: &FoundArtifact<'_>,
    pages_written: &mut HashSet<String>,
    batch: &mut Vec<Write>,
) {
    let artifact = found.artifact;
    for sighting in found.sightings {
        let id = page_id(&sighting.shard, &sighting.page_url);
        if pages_written.insert(id.clone()) {
            let fields = [
                ("page_url", sighting.page_url.clone()),
                ("date", sighting.date.clone()),
                ("shard", sighting.shard.to_string()),
            ];
            push_fields(batch, &format!("page:{id}"), fields);
        }
        batch.push(Write::SetAdd {
            key: format!("{kind}:{artifact}"),
            member: id.clone(),
        });
        batch.push(Write::SetAdd {
            key: format!("page:{id}:{kind}"),
            member: artifact.to_string(),
        });
    }

    if let Some(image) = found.image {
        let mmh3 = image.mmh3.to_string();
        let fields = [
            ("media_type", image.media_type.clone()),
            ("mmh3", mmh3.clone()),
            ("sha1", image.sha1.clone()),
            ("md5", image.md5.clone()),
        ];
        push_fields(batch, &format!("image:{artifact}"), fields);
        // A hash given by another tool leads to the image's key. Several
        // images can share one mmh3: its set then lists them all.
        for index in [
            format!("mmh3:{mmh3}"),
            format!("sha1:{}", image.sha1),
            format!("md5:{}", image.md5),
        ] {
            batch.push(Write::SetAdd {
                key: index,
                member: artifact.to_string(),
            });
        }
    }

    batch.push(Write::SetAdd {
        key: artifacts_key(kind),
        member: artifact.to_string(),
    });
}

/// Send `batch` to `store` and empty it; returns how many of its writes
/// added an Artifact new to the set at `artifacts_key`.
async fn send_batch(
    store: &mut impl Store,
    batch: &mut Vec<Write>,
    artifacts_key: &str,
) -> StoreResult<usize> {
    if batch.is_empty() {
        return Ok(0);
    }
    let changed = store.write(batch).await?;
    let new_artifacts = batch
        .iter()
        .zip(changed)
        .filter(|(write, changed)| {
            *changed && matches!(write, Write::SetAdd { key, .. } if key == artifacts_key)
        })
        .count();
    batch.clear();
    Ok(new_artifacts)
}

/// Write `kind`'s Findings in `shard`, then mark the pair done. Adds to
/// `new_artifacts` how many Artifacts were new to the store.
///
/// ## A count that survives an error
///
/// The count is added to as each batch is acknowledged, rather than
/// returned at the end: a `Result` that is an `Err` carries no count, and
/// the Artifacts added by the batches before a failure would never be
/// counted, since the redo finds them already in the store. Those the
/// failing batch added are lost all the same: its replies are lost with it.
///
/// ## Ordering for crash safety
///
/// The mark is added to `processed` only once every write of the Findings
/// was acknowledged: `?` returns at the first failed batch, before it. A
/// process killed, or a connection lost, in between leaves the pair
/// undone, never marked with Sightings missing. The next run does the pair
/// again, which writes the same members and fields, and changes nothing.
///
/// A transaction (`MULTI` / `EXEC`) would apply the writes and the mark all
/// at once instead, but kvrocks runs `EXEC` under a lock that stops every
/// other client, for one Shard's 200,000 writes. Order gives the same
/// guarantee without it.
pub async fn save_then_mark(
    store: &mut impl Store,
    kind: ArtifactKind,
    findings: &Findings,
    shard: &Shard,
    new_artifacts: &mut usize,
) -> StoreResult<()> {
    let artifacts = artifacts_key(kind);
    let mut pages_written = HashSet::new();
    let mut batch = Vec::with_capacity(BATCH_SIZE);

    for found in found_artifacts(findings) {
        push_writes(kind, &found, &mut pages_written, &mut batch);
        if batch.len() >= BATCH_SIZE {
            *new_artifacts += send_batch(store, &mut batch, &artifacts).await?;
        }
    }
    *new_artifacts += send_batch(store, &mut batch, &artifacts).await?;

    let mark = Write::SetAdd {
        key: PROCESSED_KEY.to_string(),
        member: format!("{shard} {kind}"),
    };
    store.write(&[mark]).await?;
    Ok(())
}

/// The (Shard, Artifact kind) pairs already done: the members of
/// `processed`, each `<shard> <kind>`, such as
/// `CC-MAIN-20250101000000-20250101010101-00000 onion`.
///
/// A member without a kind this version knows (written by a later version,
/// or by hand) is ignored: the pairs it might mean are done again.
///
/// ## `HashSet` of tuples
///
/// `HashSet` stores unique values with O(1) average-case lookup via hashing.
/// A tuple is hashable when each of its fields is, so `(Shard, ArtifactKind)`
/// works as a key with no extra code, and "is `onion` done for this Shard?"
/// is one `contains(&(shard, kind))`.
pub async fn load_processed(store: &mut impl Store) -> StoreResult<HashSet<(Shard, ArtifactKind)>> {
    let members = store.members(PROCESSED_KEY).await?;
    let processed = members
        .iter()
        // `filter_map` drops the members for which the closure returns
        // `None`; `?` inside it returns that `None` early.
        .filter_map(|member| {
            let (shard, kind) = member.split_once(' ')?;
            let kind = kind.parse::<ArtifactKind>().ok()?;
            // A Shard id has no Format suffix, so it is kept whole.
            Some((Shard::from_archive_name(shard), kind))
        })
        .collect();
    Ok(processed)
}

/// How many Artifacts of `kind` the store holds.
pub async fn artifact_count(store: &mut impl Store, kind: ArtifactKind) -> StoreResult<usize> {
    store.count(&artifacts_key(kind)).await
}

// ---------------------------------------------------------------------------
// Failure records
// ---------------------------------------------------------------------------

/// How many runs must count a failure on an Archive before it is given up:
/// no Plan reading it is scheduled again until its records are deleted.
pub const GIVE_UP_AFTER: usize = 3;

/// The set listing every counted failure, `<archive> <run>`.
const FAILURES_KEY: &str = "failures";

/// The hash holding the error message of each run that counted a failure
/// on `archive`.
fn failures_key(archive: &str) -> String {
    format!("{FAILURES_KEY}:{archive}")
}

/// One run of the crawl, as its failure records name it: when it started,
/// since the Unix epoch, to the nanosecond, and its process id, written
/// `<seconds>.<nanoseconds>-<process id>`.
///
/// Two runs share a `RunId` only if they started in the same nanosecond in
/// processes with the same id: never on one machine, where two processes
/// running at once have different ids, and as good as never on two
/// machines whose stores are combined. So each run's failure is a record of
/// its own.
///
/// ## Ordering by deriving `Ord`
///
/// `#[derive(PartialOrd, Ord)]` compares two structs field by field, in
/// the order the fields are declared: by start time first (`Duration` is
/// `Ord` itself), the process id deciding only between runs started at the
/// same instant. The latest run is then simply the largest `RunId`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RunId {
    started: Duration,
    process: u32,
}

impl RunId {
    /// The run that started `started` after the Unix epoch, in the process
    /// `process`.
    pub fn new(started: Duration, process: u32) -> Self {
        RunId { started, process }
    }

    /// This run: started now, in this process.
    ///
    /// `duration_since` fails only if the system clock is set before 1970;
    /// such a run is taken as started at 0, as old as runs come.
    pub fn now() -> Self {
        let started = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        RunId::new(started, process::id())
    }
}

/// `{:09}` pads the nanoseconds to nine digits: `.000000500` is 500 ns,
/// where `.500` would read as half a second.
impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{:09}-{}",
            self.started.as_secs(),
            self.started.subsec_nanos(),
            self.process
        )
    }
}

/// Reads back what `Display` writes.
impl FromStr for RunId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid = || format!("not a run: {value}");
        let (started, process) = value.split_once('-').ok_or_else(invalid)?;
        let (seconds, nanos) = started.split_once('.').ok_or_else(invalid)?;
        let nanos: u32 = nanos.parse().map_err(|_| invalid())?;
        if nanos >= 1_000_000_000 {
            return Err(invalid());
        }
        Ok(RunId {
            started: Duration::new(seconds.parse().map_err(|_| invalid())?, nanos),
            process: process.parse().map_err(|_| invalid())?,
        })
    }
}

/// What the store holds about one Archive's counted failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailureRecord {
    /// How many runs counted a failure on it.
    pub runs: usize,
    /// The error message of the latest of those runs.
    pub last_error: String,
}

impl FailureRecord {
    /// Whether the Archive is given up: no Plan reading it is scheduled.
    pub fn given_up(&self) -> bool {
        self.runs >= GIVE_UP_AFTER
    }
}

/// Record that `run` counted a failure on `archive` (its file name), with
/// `message`. Returns whether the record is new: a run records an Archive's
/// failure once, a second record changing nothing.
///
/// Two writes, both only adding: the message joins the Archive's hash,
/// under the run, then `<archive> <run>` joins `failures`. In that order, a
/// reader finding the record listed finds its message too.
pub async fn record_failure(
    store: &mut impl Store,
    run: &RunId,
    archive: &str,
    message: &str,
) -> StoreResult<bool> {
    let writes = [
        Write::HashSetIfAbsent {
            key: failures_key(archive),
            field: run.to_string(),
            value: message.to_string(),
        },
        Write::SetAdd {
            key: FAILURES_KEY.to_string(),
            member: format!("{archive} {run}"),
        },
    ];
    let changed = store.write(&writes).await?;
    Ok(changed.into_iter().any(|changed| changed))
}

/// Each Archive with failures counted, by file name, with what the store
/// holds about them. Reads `failures`, then the hashes of the Archives it
/// lists, all at once: two round trips, whatever the number of Shards or
/// failures.
///
/// ## A record in two keys
///
/// A failure counts only when both keys hold it: its member in `failures`
/// *and* its run's field in `failures:<archive>`. Writes can only add, so
/// retrying an Archive is done by deleting keys, and either deletion starts
/// a count over:
///
/// - `DEL failures:<archive>` removes one Archive's runs: the members left
///   in `failures` find no field, and count nothing.
/// - `DEL failures` removes every Archive's runs: the hashes left behind
///   are no longer listed. A later failure lists only its own run, so the
///   old fields beside it count nothing either.
///
/// A record half-written (a process killed between the two writes) counts
/// nothing: the failure is counted again on a later run, if it repeats.
pub async fn load_failures(store: &mut impl Store) -> StoreResult<HashMap<String, FailureRecord>> {
    // The runs `failures` lists for each Archive.
    let mut listed: HashMap<String, HashSet<String>> = HashMap::new();
    for member in store.members(FAILURES_KEY).await? {
        if let Some((archive, run)) = member.split_once(' ') {
            listed
                .entry(archive.to_string())
                .or_default()
                .insert(run.to_string());
        }
    }

    // `unzip` splits the pairs into two lists in the same order: the
    // Archives, and the runs listed for each.
    let (archives, listed_runs): (Vec<String>, Vec<HashSet<String>>) = listed.into_iter().unzip();
    let keys: Vec<String> = archives
        .iter()
        .map(|archive| failures_key(archive))
        .collect();
    let hashes = store.fields_of_each(&keys).await?;

    let mut failures = HashMap::new();
    for ((archive, runs), messages) in archives.into_iter().zip(listed_runs).zip(hashes) {
        // The runs both keys hold, with their messages; a field that isn't
        // a run (written by hand) counts nothing, like an unknown kind in
        // `processed`.
        let counted: Vec<(RunId, String)> = messages
            .into_iter()
            .filter(|(run, _)| runs.contains(run))
            .filter_map(|(run, message)| Some((run.parse().ok()?, message)))
            .collect();
        let count = counted.len();
        // `max_by_key` on an empty list is `None`: nothing counts.
        if let Some((_, last_error)) = counted.into_iter().max_by_key(|&(run, _)| run) {
            let record = FailureRecord {
                runs: count,
                last_error,
            };
            failures.insert(archive, record);
        }
    }
    Ok(failures)
}

// ---------------------------------------------------------------------------
// Where the store is
// ---------------------------------------------------------------------------

/// The socket `--kvrocks` names when not given.
pub const DEFAULT_SOCKET: &str = "/tmp/kvrocks.sock";

/// The environment variable holding the store's password, if it needs one.
/// kvrocks gives each namespace its own password: the one sent decides
/// which namespace the writes go to.
pub const PASSWORD_VARIABLE: &str = "CC_EXTRACT_KVROCKS_PASSWORD";

/// Where the store listens, as `--kvrocks` gives it: a Unix socket path, or
/// a `redis://host:port` URL.
///
/// ## Why TCP too
///
/// A Unix socket reaches a store on the same machine, without the network
/// stack. kvrocks has no macOS build that runs well, and in Docker Desktop
/// a container runs in a Linux virtual machine: a socket it creates in a
/// shared directory shows up on the Mac, but can't be connected to from
/// there. Its published TCP port can.
///
/// The password is never part of the URL: a URL given on the command line
/// shows in `ps` and in shell history. It comes from `PASSWORD_VARIABLE`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreAddress {
    /// A Unix socket.
    Socket(PathBuf),
    /// A TCP host (a name or an IP address) and port.
    Tcp { host: String, port: u16 },
}

/// The form a URL must have.
const URL_FORM: &str = "redis://host:port";

impl FromStr for StoreAddress {
    type Err = String;

    /// A value with `://` is a URL, anything else a socket path.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if !value.contains("://") {
            return Ok(StoreAddress::Socket(PathBuf::from(value)));
        }
        let url = Url::parse(value).map_err(|err| format!("invalid URL: {err}"))?;
        if url.scheme() != "redis" {
            return Err(format!(
                "give a Unix socket path or a {URL_FORM} URL, not {}://",
                url.scheme()
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(format!(
                "give the password in {PASSWORD_VARIABLE}, not in the URL"
            ));
        }
        if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
            return Err(format!(
                "give the URL as {URL_FORM}, with nothing after the port"
            ));
        }
        // `Host::Ipv6` holds the address without the brackets the URL
        // writes it in, which the connection wants.
        let host = match url.host() {
            Some(Host::Domain(name)) => name.to_string(),
            Some(Host::Ipv4(ip)) => ip.to_string(),
            Some(Host::Ipv6(ip)) => ip.to_string(),
            None => return Err(format!("give the URL as {URL_FORM}: no host")),
        };
        let port = url
            .port()
            .ok_or_else(|| format!("give the URL as {URL_FORM}: no port"))?;
        Ok(StoreAddress::Tcp { host, port })
    }
}

impl StoreAddress {
    /// A `redis` client for the store at this address, sending `password`
    /// with `AUTH` when it connects, if given. Nothing is connected yet.
    pub fn client(&self, password: Option<String>) -> redis::RedisResult<redis::Client> {
        let addr = match self {
            #[cfg(unix)]
            StoreAddress::Socket(path) => ConnectionAddr::Unix(path.clone()),
            #[cfg(not(unix))]
            StoreAddress::Socket(_) => {
                return Err(redis::RedisError::from((
                    redis::ErrorKind::InvalidClientConfig,
                    "Unix sockets need a Unix system: give a redis://host:port URL",
                )));
            }
            StoreAddress::Tcp { host, port } => ConnectionAddr::Tcp(host.clone(), *port),
        };
        let mut settings = RedisConnectionInfo::default();
        if let Some(password) = password {
            settings = settings.set_password(password);
        }
        let info = addr.into_connection_info()?.set_redis_settings(settings);
        redis::Client::open(info)
    }
}

/// The address as it was given, for messages.
impl fmt::Display for StoreAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreAddress::Socket(path) => write!(f, "{}", path.display()),
            // An IPv6 address goes between brackets, or its colons would
            // run into the port's.
            StoreAddress::Tcp { host, port } if host.contains(':') => {
                write!(f, "redis://[{host}]:{port}")
            }
            StoreAddress::Tcp { host, port } => write!(f, "redis://{host}:{port}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(host: &str, port: u16) -> StoreAddress {
        StoreAddress::Tcp {
            host: host.to_string(),
            port,
        }
    }

    #[test]
    fn a_run_reads_back_as_written() {
        let run = RunId::new(Duration::new(1_735_689_600, 500), 4242);
        // The nanoseconds padded: 500 ns, not half a second.
        assert_eq!(run.to_string(), "1735689600.000000500-4242");
        assert_eq!("1735689600.000000500-4242".parse(), Ok(run));
        for not_a_run in ["1735689600-4242", "1735689600.1000000000-4242", "x.0-1"] {
            assert!(not_a_run.parse::<RunId>().is_err(), "{not_a_run}");
        }
    }

    #[test]
    fn a_path_is_a_unix_socket() {
        for path in ["/tmp/kvrocks.sock", "kvrocks.sock", "run/kvrocks.sock"] {
            assert_eq!(
                path.parse::<StoreAddress>(),
                Ok(StoreAddress::Socket(PathBuf::from(path)))
            );
        }
    }

    #[test]
    fn a_redis_url_is_a_tcp_host_and_port() {
        let urls = [
            ("redis://127.0.0.1:16666", tcp("127.0.0.1", 16666)),
            ("redis://localhost:6666/", tcp("localhost", 6666)),
            ("redis://[::1]:6666", tcp("::1", 6666)),
        ];
        for (url, address) in urls {
            assert_eq!(url.parse::<StoreAddress>(), Ok(address), "{url}");
        }
    }

    #[test]
    fn an_address_displays_as_it_is_given() {
        for given in [
            "/tmp/kvrocks.sock",
            "redis://localhost:6666",
            "redis://[::1]:6666",
        ] {
            let address: StoreAddress = given.parse().unwrap();
            assert_eq!(address.to_string(), given);
        }
    }

    #[test]
    fn a_password_in_the_url_is_refused() {
        // A URL on the command line shows in `ps` and in shell history.
        for url in [
            "redis://:secret@localhost:6666",
            "redis://user@localhost:6666",
        ] {
            let error = url.parse::<StoreAddress>().unwrap_err();
            assert!(error.contains(PASSWORD_VARIABLE), "{url}: {error}");
        }
    }

    #[test]
    fn urls_the_store_cannot_use_are_refused() {
        let refused = [
            // kvrocks listens on 6666, Redis on 6379: no default to guess.
            ("redis://localhost", "port"),
            // kvrocks has namespaces, chosen by the password, not databases.
            ("redis://localhost:6666/2", "redis://host:port"),
            ("redis://localhost:6666?timeout=1", "redis://host:port"),
            ("rediss://localhost:6666", "redis://host:port"),
            ("unix:///tmp/kvrocks.sock", "redis://host:port"),
        ];
        for (url, expected) in refused {
            let error = url.parse::<StoreAddress>().unwrap_err();
            assert!(error.contains(expected), "{url}: {error}");
        }
    }
}
