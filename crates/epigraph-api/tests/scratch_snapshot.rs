//! Durable snapshots of the scratch graph (DESIGN §4.2 "Durability", task E1).
//!
//! The runner relies on three properties: a write never leaves both files
//! unusable, restore falls back to `.prev` when `graph.json` is damaged, and a
//! torn tmp file is never read. Each test damages real files on disk.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use chrono::{DateTime, TimeZone, Utc};
use epigraph_api::scratch::snapshot::{
    self, decode, encode, prev_path, restore, tmp_path, write_atomic, DecodeError, RestoreError,
    RestoredFrom,
};
use epigraph_api::scratch::store::{
    AtomKind, Evidence, NewAtom, NewEdge, Relationship, ScratchStore, Seed, Speaker,
};
use uuid::Uuid;

const SCOPE: &str = "3f9a1c07be52";

fn t(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_790_000_000 + secs, 0).unwrap()
}

fn id(n: u128) -> Uuid {
    Uuid::from_u128(0x0b5e_0000_0000_0000_0000_0000_0000_0000 + n)
}

/// A fresh directory under the system temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "scratch-snapshot-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn graph(&self) -> PathBuf {
        self.0.join("graph.json")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn new_atom(n: u128, turn: u64, text: &str, supported: f64) -> NewAtom {
    NewAtom {
        id: id(n),
        text: text.to_string(),
        kind: AtomKind::Decision,
        speaker: Speaker::User,
        turn,
        epoch: 4,
        quote: Some(text.chars().take(12).collect()),
        evidence: vec![Evidence {
            path: format!("turns/{turn}.json"),
            sha256: "0123456789abcdef".repeat(4),
            span: Some("tool:2".into()),
            quote: None,
        }],
        seed: Seed { supported },
    }
}

/// A graph exercising every stored shape: awkward floats, unicode, escapes,
/// quotes, a superseded atom, a corroboration, edges and applied turns.
fn rich_store() -> ScratchStore {
    let mut s = ScratchStore::new(SCOPE, 4, t(0));
    s.put_atoms(
        vec![
            new_atom(
                3,
                7,
                "The operator decided: \"v2 probes\" only — no v1.\n\tTabs \\ backslashes.",
                1.0 / 3.0,
            ),
            new_atom(
                1,
                2,
                "Größe 40 m² · 測試 · emoji 🌱 · NUL-free \u{7f} control",
                0.1,
            ),
            new_atom(
                2,
                9,
                "Probe count per bed changed from 2 to 3.",
                0.712_345_678_9,
            ),
            new_atom(4, 9, "A later correction.", 2.0 / 3.0),
        ],
        t(1),
    )
    .unwrap();
    s.corroborate(
        id(90),
        id(3),
        Seed {
            supported: 0.300_000_000_000_000_04,
        },
        vec![],
        t(2),
    )
    .unwrap();
    s.add_edges(
        vec![
            NewEdge {
                id: id(60),
                source: id(2),
                target: id(3),
                rel: Relationship::Elaborates,
            },
            NewEdge {
                id: id(50),
                source: id(1),
                target: id(3),
                rel: Relationship::Contradicts,
            },
        ],
        t(3),
    )
    .unwrap();
    s.supersede(id(2), id(4), t(4)).unwrap();
    s.mark_applied(9, t(5));
    s.mark_applied(2, t(6));
    s.mark_applied(7, t(7));
    s
}

#[test]
fn write_restore_write_is_byte_identical() {
    let dir = TempDir::new("roundtrip");
    let store = rich_store();
    let first = encode(&store);
    write_atomic(&dir.graph(), &first).unwrap();

    // Restore into a NEW store from disk, then write it again.
    let (restored, report) = restore(&dir.graph(), SCOPE, 4, t(999)).unwrap();
    assert_eq!(report.from, RestoredFrom::Snapshot);
    assert!(!report.degraded());
    assert_eq!(restored, store);
    let second = encode(&restored);
    assert_eq!(
        second, first,
        "restore -> encode must reproduce the file byte for byte"
    );
    write_atomic(&dir.graph(), &second).unwrap();
    assert_eq!(fs::read(dir.graph()).unwrap(), first);

    // The bytes do not depend on insertion order: the same graph built in a
    // different order encodes identically.
    let mut other = ScratchStore::new(SCOPE, 4, t(0));
    other
        .put_atoms(vec![new_atom(4, 9, "A later correction.", 2.0 / 3.0)], t(1))
        .unwrap();
    other
        .put_atoms(
            vec![
                new_atom(
                    2,
                    9,
                    "Probe count per bed changed from 2 to 3.",
                    0.712_345_678_9,
                ),
                new_atom(
                    1,
                    2,
                    "Größe 40 m² · 測試 · emoji 🌱 · NUL-free \u{7f} control",
                    0.1,
                ),
                new_atom(
                    3,
                    7,
                    "The operator decided: \"v2 probes\" only — no v1.\n\tTabs \\ backslashes.",
                    1.0 / 3.0,
                ),
            ],
            t(1),
        )
        .unwrap();
    other
        .corroborate(
            id(90),
            id(3),
            Seed {
                supported: 0.300_000_000_000_000_04,
            },
            vec![],
            t(2),
        )
        .unwrap();
    other
        .add_edges(
            vec![
                NewEdge {
                    id: id(50),
                    source: id(1),
                    target: id(3),
                    rel: Relationship::Contradicts,
                },
                NewEdge {
                    id: id(60),
                    source: id(2),
                    target: id(3),
                    rel: Relationship::Elaborates,
                },
            ],
            t(3),
        )
        .unwrap();
    other.supersede(id(2), id(4), t(4)).unwrap();
    for turn in [7, 2] {
        other.mark_applied(turn, t(5));
    }
    other.mark_applied(9, t(7));
    assert_eq!(encode(&other), first);
}

#[test]
fn the_file_is_one_object_with_the_design_fields_and_a_verifiable_hash() {
    let bytes = encode(&rich_store());
    assert!(bytes.ends_with(b"\"}\n"));
    assert_eq!(bytes.iter().filter(|b| **b == b'\n').count(), 1, "one line");
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    let mut expected = vec![
        "format",
        "scope",
        "epoch",
        "applied_turns",
        "atoms",
        "edges",
        "built_at",
        "sha256",
    ];
    expected.sort_unstable();
    assert_eq!(keys, expected);
    assert_eq!(v["format"], 1);
    assert_eq!(v["applied_turns"], serde_json::json!([2, 7, 9]));
    assert_eq!(
        v["atoms"][0]["id"],
        id(1).to_string(),
        "atoms are in id order"
    );
    assert_eq!(
        v["edges"][0]["id"],
        id(50).to_string(),
        "edges are in id order"
    );

    // The hash is the SHA-256 of the object without its sha256 member.
    use sha2::{Digest, Sha256};
    let mut without = v.clone();
    without.as_object_mut().unwrap().remove("sha256");
    let text = String::from_utf8(bytes.clone()).unwrap();
    let body = format!("{}}}", &text[..text.rfind(",\"sha256\"").unwrap()]);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap(),
        without
    );
    assert_eq!(v["sha256"], hex::encode(Sha256::digest(body.as_bytes())));
}

#[test]
fn an_edited_snapshot_fails_its_hash_and_restore_falls_back_to_prev() {
    let dir = TempDir::new("tamper");
    let older = {
        let mut s = ScratchStore::new(SCOPE, 4, t(0));
        s.put_atoms(
            vec![new_atom(1, 1, "The pilot site has 40 beds.", 0.5)],
            t(1),
        )
        .unwrap();
        s
    };
    write_atomic(&dir.graph(), &encode(&older)).unwrap();
    let newer = rich_store();
    write_atomic(&dir.graph(), &encode(&newer)).unwrap();
    assert_eq!(
        fs::read(prev_path(&dir.graph())).unwrap(),
        encode(&older),
        "the write kept the previous file as .prev"
    );

    // Edit the newest snapshot: still valid JSON, but the content changed.
    let edited = String::from_utf8(fs::read(dir.graph()).unwrap())
        .unwrap()
        .replace("to 3.", "to 4.");
    fs::write(dir.graph(), &edited).unwrap();
    assert_eq!(decode(edited.as_bytes()), Err(DecodeError::HashMismatch));

    let (restored, report) = restore(&dir.graph(), SCOPE, 4, t(9)).unwrap();
    assert_eq!(report.from, RestoredFrom::Prev);
    assert_eq!(report.snapshot_problem, Some("hash_mismatch"));
    assert!(report.degraded());
    assert_eq!(restored, older);
}

#[test]
fn a_truncated_snapshot_falls_back_to_prev_at_every_cut() {
    let dir = TempDir::new("truncate");
    let older = rich_store();
    let mut newer = older.clone();
    newer.mark_applied(10, t(50));
    write_atomic(&dir.graph(), &encode(&older)).unwrap();
    let full = encode(&newer);
    write_atomic(&dir.graph(), &full).unwrap();

    for cut in [
        0,
        1,
        full.len() / 3,
        full.len() / 2,
        full.len() - 3,
        full.len() - 2,
    ] {
        fs::write(dir.graph(), &full[..cut]).unwrap();
        let (restored, report) = restore(&dir.graph(), SCOPE, 4, t(9)).unwrap();
        assert_eq!(report.from, RestoredFrom::Prev, "cut at {cut}");
        assert_eq!(restored, older, "cut at {cut}");
    }
    // Losing only the trailing newline is not damage.
    fs::write(dir.graph(), &full[..full.len() - 1]).unwrap();
    let (restored, report) = restore(&dir.graph(), SCOPE, 4, t(9)).unwrap();
    assert_eq!((report.from, restored), (RestoredFrom::Snapshot, newer));
}

#[test]
fn a_missing_snapshot_uses_prev_the_crash_window_between_renames() {
    let dir = TempDir::new("window");
    let store = rich_store();
    write_atomic(&dir.graph(), &encode(&store)).unwrap();
    // Simulate a crash after `graph.json -> .prev` and before `tmp -> graph.json`.
    fs::rename(dir.graph(), prev_path(&dir.graph())).unwrap();
    fs::write(tmp_path(&dir.graph()), b"{\"format\":1,\"sco").unwrap();

    let (restored, report) = restore(&dir.graph(), SCOPE, 4, t(9)).unwrap();
    assert_eq!(report.from, RestoredFrom::Prev);
    assert_eq!(report.snapshot_problem, Some("missing"));
    assert!(!report.degraded(), "a missing file is not damage");
    assert_eq!(restored, store);
}

#[test]
fn a_torn_tmp_file_is_never_read_and_is_replaced_by_the_next_write() {
    let dir = TempDir::new("torn");
    let store = rich_store();
    write_atomic(&dir.graph(), &encode(&store)).unwrap();
    // A torn tmp: and a tmp that is a whole, valid snapshot of a DIFFERENT
    // graph. Neither may be restored from.
    for tmp_content in [
        b"{\"format\":1,\"atoms\":[{\"id\"".to_vec(),
        encode(&ScratchStore::new(SCOPE, 4, t(77))),
    ] {
        fs::write(tmp_path(&dir.graph()), &tmp_content).unwrap();
        let (restored, report) = restore(&dir.graph(), SCOPE, 4, t(9)).unwrap();
        assert_eq!(report.from, RestoredFrom::Snapshot);
        assert_eq!(restored, store);
    }
    let mut next = store.clone();
    next.mark_applied(11, t(60));
    write_atomic(&dir.graph(), &encode(&next)).unwrap();
    assert!(
        !tmp_path(&dir.graph()).exists(),
        "the write renames its tmp file into place"
    );
    assert_eq!(restore(&dir.graph(), SCOPE, 4, t(9)).unwrap().0, next);
}

#[test]
fn both_files_damaged_starts_empty_and_says_so() {
    let dir = TempDir::new("both");
    fs::write(dir.graph(), b"not json").unwrap();
    fs::write(prev_path(&dir.graph()), b"{}").unwrap();
    let (restored, report) = restore(&dir.graph(), SCOPE, 4, t(9)).unwrap();
    assert_eq!(report.from, RestoredFrom::Empty);
    assert_eq!(
        (report.snapshot_problem, report.prev_problem),
        (Some("malformed"), Some("malformed"))
    );
    assert!(
        report.degraded(),
        "the runner must backfill: every turn is unapplied"
    );
    assert_eq!(restored, ScratchStore::new(SCOPE, 4, t(9)));
    assert_eq!(restored.applied_turns().count(), 0);

    // Nothing on disk at all is a clean first start, not damage.
    let fresh = TempDir::new("fresh");
    let (_, report) = restore(&fresh.graph(), SCOPE, 4, t(9)).unwrap();
    assert_eq!(report.from, RestoredFrom::Empty);
    assert!(!report.degraded());
}

#[test]
fn an_intact_snapshot_of_another_scope_or_epoch_is_refused_not_overwritten() {
    for (scope, epoch, which_file) in [
        ("aaaaaaaaaaaa", 4, "graph"),
        (SCOPE, 3, "graph"),
        (SCOPE, 3, "prev"),
    ] {
        let dir = TempDir::new("foreign");
        let foreign = encode(&ScratchStore::new(scope, epoch, t(0)));
        let target: PathBuf = if which_file == "graph" {
            dir.graph()
        } else {
            prev_path(&dir.graph())
        };
        fs::write(&target, &foreign).unwrap();
        if which_file == "prev" {
            // graph.json damaged, so restore reaches the foreign .prev.
            fs::write(dir.graph(), b"garbage").unwrap();
        }
        let err = restore(&dir.graph(), SCOPE, 4, t(9)).unwrap_err();
        let expected = if which_file == "graph" {
            RestoredFrom::Snapshot
        } else {
            RestoredFrom::Prev
        };
        assert_eq!(err, RestoreError::Foreign { which: expected });
        assert_eq!(
            fs::read(&target).unwrap(),
            foreign,
            "the foreign file is left untouched"
        );
    }
}

#[test]
fn decode_refuses_other_formats_and_broken_invariants() {
    let good = String::from_utf8(encode(&rich_store())).unwrap();
    let rehash = |text: &str| -> Vec<u8> {
        // Re-sign an edited body so only the edit, not the hash, is at fault.
        use sha2::{Digest, Sha256};
        let body = format!("{}}}", &text[..text.rfind(",\"sha256\"").unwrap()]);
        let digest = hex::encode(Sha256::digest(body.as_bytes()));
        format!("{},\"sha256\":\"{digest}\"}}\n", &body[..body.len() - 1]).into_bytes()
    };
    assert_eq!(
        decode(&rehash(&good)).unwrap(),
        rich_store(),
        "the re-signer is faithful"
    );
    assert_eq!(
        decode(&rehash(&good.replacen("\"format\":1", "\"format\":2", 1))),
        Err(DecodeError::UnsupportedFormat(2))
    );
    let other_epoch_atom = good.replacen(
        "\"epoch\":4,\"created_at\"",
        "\"epoch\":5,\"created_at\"",
        1,
    );
    assert!(matches!(
        decode(&rehash(&other_epoch_atom)),
        Err(DecodeError::Invalid(_))
    ));
    let unknown_field = good.replacen("\"format\":1", "\"format\":1,\"extra\":true", 1);
    assert_eq!(decode(&rehash(&unknown_field)), Err(DecodeError::Malformed));
    assert_eq!(snapshot::FORMAT, 1);
}
