//! The Atlas naming step (Atlas W8, backlog a71816e1) on a fresh database:
//! a map's run is built (the meaning hierarchy through W4's write path, and a
//! synthetic links hierarchy in the same run), then named through
//! `atlas_naming::build::name_map` with a recording backend that never calls a
//! model.
//!
//! Every claim's text carries a marker (`TOKA03`, `TOKB01`, `TOKP02`: team A,
//! team B, public). The backend copies a marker of its prompt into the name it
//! returns, so a text that reached a prompt it should not have would also show
//! in a stored name; the tests check both the prompts and the names.
//!
//! The runs are built BEFORE a claim moves (narrows, or changes team), so the
//! stored documents still list it: only the map-scoped member-text read keeps
//! its text out of the names.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::{BTreeMap, BTreeSet};

use epigraph_atlas_contract::{parse_and_validate, LevelDocument};
use epigraph_cli::atlas_meaning::build::{resolve_result, write_meaning_levels};
use epigraph_cli::atlas_meaning::docs::level_documents;
use epigraph_cli::atlas_meaning::files::{ComputeVersions, ResultDoc, ResultTheme};
use epigraph_cli::atlas_meaning::tree::{
    check_tree, group_id, map_key, root_id, WireGroup, WireKind,
};
use epigraph_cli::atlas_naming::backend::RecordingBackend;
use epigraph_cli::atlas_naming::build::{name_map, NameMapOptions};
use epigraph_db::repos::atlas_map::{AtlasHierarchy, AtlasMap, NewMapRun};
use epigraph_db::{AtlasMapRepository, AtlasMeaningRepository, Viewer};
use serde_json::json;
use sqlx::{Connection, PgPool};
use uuid::Uuid;

const CAP: usize = 100;
const DIM: usize = 1536;

// ── seeding ─────────────────────────────────────────────────────────────────

async fn team(pool: &PgPool, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind) \
         VALUES ($1, $2, 'did:epigraph:test-team:' || $1::text, $3, 'team')",
    )
    .bind(id)
    .bind(label)
    .bind(&key)
    .execute(pool)
    .await
    .expect("seed team");
    id
}

async fn agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn theme(pool: &PgPool) -> Uuid {
    sqlx::query_scalar("INSERT INTO claim_themes (label) VALUES ('naming test') RETURNING id")
        .fetch_one(pool)
        .await
        .expect("seed theme")
}

fn vector(axis: usize, jitter: usize) -> String {
    let mut v = vec![0.0_f32; DIM];
    v[axis % DIM] = 1.0;
    v[(axis + 7 + jitter) % DIM] = 0.01;
    let parts: Vec<String> = v.iter().map(|x| format!("{x}")).collect();
    format!("[{}]", parts.join(","))
}

/// `n` current, embedded claims of `theme`, declared `(visibility, owner)`,
/// whose texts carry the markers `TOK{prefix}00`, `TOK{prefix}01`, ...
async fn claims(
    pool: &PgPool,
    theme: Uuid,
    filer: Uuid,
    (visibility, owner): (&str, Uuid),
    prefix: &str,
    n: usize,
) -> Vec<Uuid> {
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let content =
            format!("Measured result TOK{prefix}{i:02} holds under the stated conditions");
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                                 visibility, owner_group_id, theme_id, embedding) \
             VALUES (gen_random_uuid(), $1, \
                     decode(md5(random()::text) || md5(random()::text), 'hex'), 0.7, $2, true, \
                     $3, $4, $5, $6::vector) \
             RETURNING id",
        )
        .bind(&content)
        .bind(filer)
        .bind(visibility)
        .bind(owner)
        .bind(theme)
        .bind(vector(i * 3, i))
        .fetch_one(pool)
        .await
        .expect("seed claim");
        out.push(id);
    }
    out
}

fn marker(prefix: &str, i: usize) -> String {
    format!("TOK{prefix}{i:02}")
}

/// Two teams and the public, in one theme: team A's 12 claims, team B's 6
/// private claims and 6 public claims.
struct Corpus {
    a: Uuid,
    b: Uuid,
    theme: Uuid,
    team_a: Vec<Uuid>,
    team_b: Vec<Uuid>,
    public: Vec<Uuid>,
}

impl Corpus {
    async fn new(pool: &PgPool) -> Self {
        let a = team(pool, "naming team a").await;
        let b = team(pool, "naming team b").await;
        let world = fixture::world_group(pool).await;
        let theme = theme(pool).await;
        let filer = agent(pool).await;
        let team_a = claims(pool, theme, filer, ("group", a), "A", 12).await;
        let team_b = claims(pool, theme, filer, ("group", b), "B", 6).await;
        let public = claims(pool, theme, filer, ("public", world), "P", 6).await;
        Self {
            a,
            b,
            theme,
            team_a,
            team_b,
            public,
        }
    }
}

// ── building a run ──────────────────────────────────────────────────────────

/// One theme's grouping: its leaves; one leaf is a root leaf.
fn wire(map: AtlasMap, h: AtlasHierarchy, theme: Uuid, leaves: &[Vec<Uuid>]) -> ResultTheme {
    let root = root_id(map, h, theme);
    let set = |v: &[Uuid]| -> BTreeSet<Uuid> { v.iter().copied().collect() };
    let leaf = |id: Uuid, parent: Option<Uuid>, depth: u8, m: &BTreeSet<Uuid>| WireGroup {
        id,
        parent,
        depth,
        kind: WireKind::Leaf,
        claim_count: u32::try_from(m.len()).unwrap(),
        weight: 0,
        members: Some(m.iter().copied().collect()),
        children: None,
    };
    let groups = if leaves.len() == 1 {
        vec![leaf(root, None, 0, &set(&leaves[0]))]
    } else {
        let ids: Vec<Uuid> = leaves
            .iter()
            .map(|l| group_id(map, h, theme, &set(l)))
            .collect();
        let mut g = vec![WireGroup {
            id: root,
            parent: None,
            depth: 0,
            kind: WireKind::Group,
            claim_count: 0,
            weight: 0,
            members: None,
            children: Some(ids.clone()),
        }];
        for (l, id) in leaves.iter().zip(ids) {
            g.push(leaf(id, Some(root), 1, &set(l)));
        }
        g
    };
    ResultTheme {
        theme_id: theme,
        id_chunk_cuts: 0,
        groups,
    }
}

/// One theme of a run: its meaning leaves and its links leaves.
struct Shape {
    theme: Uuid,
    meaning: Vec<Vec<Uuid>>,
    links: Vec<Vec<Uuid>>,
}

/// Store one finished run of `map`: every theme's meaning levels through
/// W4's `write_meaning_levels`, and its links levels (a synthetic grouping
/// standing in for W5) in the same run. Params carry a stand-in W6 record,
/// which the naming must keep.
async fn build(pool: &PgPool, viewer: &Viewer, map: AtlasMap, shapes: &[Shape]) -> Uuid {
    let mut conn = pool.acquire().await.unwrap();
    let mut tx = conn.begin().await.unwrap();
    let epochs = AtlasMapRepository::begin_build_snapshot(&mut tx, viewer, map)
        .await
        .unwrap();
    let result = ResultDoc {
        format: "atlas-meaning-result/1".to_string(),
        map: map_key(map),
        hierarchy: "meaning".to_string(),
        cap: CAP,
        seed: 42,
        versions: ComputeVersions::default(),
        themes: shapes
            .iter()
            .map(|s| wire(map, AtlasHierarchy::Meaning, s.theme, &s.meaning))
            .collect(),
    };
    let resolved = resolve_result(&mut tx, viewer, map, &result, CAP)
        .await
        .expect("resolve the meaning result");
    let run = AtlasMapRepository::write_run(
        &mut tx,
        &NewMapRun {
            map,
            algo: "atlas-meaning/1".to_string(),
            params: json!({"layout": {"algo": "stand-in", "hashes": {}}}),
            epochs,
        },
    )
    .await
    .unwrap();
    write_meaning_levels(&mut tx, viewer, map, run, &resolved)
        .await
        .unwrap();
    for s in shapes {
        let members: BTreeSet<Uuid> = s.links.iter().flatten().copied().collect();
        let w = wire(map, AtlasHierarchy::Links, s.theme, &s.links);
        let tree = check_tree(map, AtlasHierarchy::Links, s.theme, &w.groups, &members).unwrap();
        let all: Vec<Uuid> = members.iter().copied().collect();
        let labels = AtlasMeaningRepository::claim_labels(&mut tx, viewer, map, &all)
            .await
            .unwrap();
        for d in level_documents(&tree, run, &labels).unwrap() {
            AtlasMapRepository::put_level(&mut tx, run, &d)
                .await
                .unwrap();
        }
    }
    AtlasMapRepository::finish_run(&mut tx, run).await.unwrap();
    tx.commit().await.unwrap();
    run
}

// ── naming ──────────────────────────────────────────────────────────────────

/// Every `TOK…` marker in `s`.
fn markers(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.starts_with("TOK"))
        .map(str::to_string)
        .collect()
}

/// A backend that names a group after the smallest marker in its prompt.
fn echo() -> RecordingBackend {
    RecordingBackend::new(|prompt: &str| {
        let m = markers(prompt)
            .into_iter()
            .min()
            .unwrap_or_else(|| "none".into());
        Ok(format!("{{\"name\": \"Topic {m}\"}}"))
    })
}

async fn name(
    pool: &PgPool,
    viewer: &Viewer,
    map: AtlasMap,
    backend: &RecordingBackend,
) -> serde_json::Value {
    let mut conn = pool.acquire().await.unwrap();
    name_map(
        &mut conn,
        viewer,
        backend,
        NameMapOptions {
            map,
            write: true,
            max_calls: None,
        },
    )
    .await
    .expect("name the map")
}

fn run_of(report: &serde_json::Value) -> Uuid {
    serde_json::from_value(report["run_id"].clone()).expect("a written run")
}

/// One stored level.
#[derive(Debug, Clone, sqlx::FromRow)]
struct Stored {
    hierarchy: String,
    group_id: Uuid,
    payload: serde_json::Value,
}

async fn stored(pool: &PgPool, run: Uuid) -> Vec<Stored> {
    sqlx::query_as(
        "SELECT hierarchy, group_id, payload FROM atlas_map_levels WHERE run_id = $1 \
          ORDER BY hierarchy, level, group_id",
    )
    .bind(run)
    .fetch_all(pool)
    .await
    .unwrap()
}

/// Every name a stored run holds anywhere (own, children, breadcrumbs).
fn names_in(levels: &[Stored]) -> Vec<String> {
    let mut out = Vec::new();
    for l in levels {
        let s = l.payload.to_string();
        let doc: LevelDocument = serde_json::from_str(&s).unwrap();
        match doc {
            LevelDocument::Group(g) => {
                out.extend(g.name);
                out.extend(g.children.into_iter().filter_map(|c| c.name));
                out.extend(g.breadcrumbs.into_iter().filter_map(|b| b.name));
            }
            LevelDocument::Leaf(l) => {
                out.extend(l.name);
                out.extend(l.breadcrumbs.into_iter().filter_map(|b| b.name));
            }
        }
    }
    out
}

fn own_names(levels: &[Stored]) -> BTreeMap<(String, Uuid), Option<String>> {
    levels
        .iter()
        .map(|l| {
            let n = l.payload["name"].as_str().map(str::to_string);
            ((l.hierarchy.clone(), l.group_id), n)
        })
        .collect()
}

/// Team A's map: meaning in two leaves, links in a different two.
fn team_a_shape(c: &Corpus) -> Shape {
    let (a, p) = (&c.team_a, &c.public);
    Shape {
        theme: c.theme,
        meaning: vec![
            a[0..6].iter().chain(&p[0..3]).copied().collect(),
            a[6..12].iter().chain(&p[3..6]).copied().collect(),
        ],
        links: vec![
            a[0..4].iter().chain(p).copied().collect(),
            a[4..12].to_vec(),
        ],
    }
}

fn public_shape(c: &Corpus) -> Shape {
    Shape {
        theme: c.theme,
        meaning: vec![c.public[0..3].to_vec(), c.public[3..6].to_vec()],
        links: vec![c.public.clone()],
    }
}

// ── the tests ───────────────────────────────────────────────────────────────

/// Done when: a team map's names never draw on another team's private text.
/// Team B's private claims share the theme; after the build a team-A claim
/// moves to team B, so A's stored leaf still lists it. No prompt for A's map
/// holds a team-B marker or the moved claim's marker, and no stored name
/// does; team B's map, named too, never sees team A's text.
#[sqlx::test(migrations = "../../migrations")]
async fn a_team_maps_names_never_draw_on_another_teams_private_text(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let map_a = AtlasMap::Team(c.a);
    let map_b = AtlasMap::Team(c.b);
    build(&pool, &viewer, map_a, &[team_a_shape(&c)]).await;
    let b_members: Vec<Uuid> = c.team_b.iter().chain(&c.public).copied().collect();
    build(
        &pool,
        &viewer,
        map_b,
        &[Shape {
            theme: c.theme,
            meaning: vec![b_members.clone()],
            links: vec![b_members],
        }],
    )
    .await;
    let moved = c.team_a[2];
    sqlx::query("UPDATE claims SET owner_group_id = $2 WHERE id = $1")
        .bind(moved)
        .bind(c.b)
        .execute(&pool)
        .await
        .unwrap();

    let fake_a = echo();
    let report = name(&pool, &viewer, map_a, &fake_a).await;
    assert!(fake_a.calls() >= 5, "{report}");
    let prompts = fake_a.prompts().join("\n");
    assert!(
        prompts.contains("TOKA00"),
        "the prompts carry team A's text"
    );
    assert!(prompts.contains("TOKP00"), "and public text");
    for (i, _) in c.team_b.iter().enumerate() {
        assert!(
            !prompts.contains(&marker("B", i)),
            "team B's text reached A's prompts"
        );
    }
    assert!(
        !prompts.contains(&marker("A", 2)),
        "the moved claim's text reached A's prompts"
    );
    for n in names_in(&stored(&pool, run_of(&report)).await) {
        assert!(!n.contains("TOKB") && !n.contains(&marker("A", 2)), "{n}");
    }

    let fake_b = echo();
    name(&pool, &viewer, map_b, &fake_b).await;
    let prompts = fake_b.prompts().join("\n");
    assert!(prompts.contains("TOKB00"));
    assert!(
        !prompts.contains("TOKA"),
        "team A's text reached B's prompts"
    );
}

/// The public map's prompts hold only public text: after the build a public
/// claim narrows to a team, and every marker in every public-map prompt is a
/// claim that is public now.
#[sqlx::test(migrations = "../../migrations")]
async fn the_public_maps_prompts_hold_only_public_text(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    build(&pool, &viewer, AtlasMap::Public, &[public_shape(&c)]).await;
    let narrowed = c.public[1];
    sqlx::query("UPDATE claims SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(narrowed)
        .bind(c.a)
        .execute(&pool)
        .await
        .unwrap();

    let fake = echo();
    let report = name(&pool, &viewer, AtlasMap::Public, &fake).await;
    assert!(fake.calls() >= 3, "{report}");
    let public_now: BTreeSet<String> = c
        .public
        .iter()
        .enumerate()
        .filter(|(_, id)| **id != narrowed)
        .map(|(i, _)| marker("P", i))
        .collect();
    let mut seen = 0;
    for p in fake.prompts() {
        for m in markers(&p) {
            assert!(
                public_now.contains(&m),
                "{m} is not a public claim's marker: {p}"
            );
            seen += 1;
        }
    }
    assert!(seen > 0, "the prompts carry public text");
    assert!(!fake.prompts().join("\n").contains(&marker("P", 1)));
}

/// A name drawn from a claim that was public is replaced once the claim
/// narrows, even though the stored documents (and every group id) are
/// unchanged: the carry-over key covers the sampled texts, not the group id.
#[sqlx::test(migrations = "../../migrations")]
async fn a_name_drawn_from_a_claim_that_narrowed_is_replaced(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    build(&pool, &viewer, AtlasMap::Public, &[public_shape(&c)]).await;
    let first = name(&pool, &viewer, AtlasMap::Public, &echo()).await;
    let token = marker("P", 0);
    let before = names_in(&stored(&pool, run_of(&first)).await);
    assert!(
        before.iter().any(|n| n.contains(&token)),
        "precondition: a name drew on {token}: {before:?}"
    );

    sqlx::query("UPDATE claims SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(c.public[0])
        .bind(c.a)
        .execute(&pool)
        .await
        .unwrap();
    let fake = echo();
    let second = name(&pool, &viewer, AtlasMap::Public, &fake).await;
    assert!(fake.calls() >= 1, "{second}");
    let after = names_in(&stored(&pool, run_of(&second)).await);
    assert!(!after.is_empty());
    for n in &after {
        assert!(
            !n.contains(&token),
            "a name still draws on the narrowed claim: {n}"
        );
    }
}

/// Done when: a rerun over unchanged groups makes zero LLM calls. The next
/// night's build (same input, names null again) is named with no call and
/// every name copied; naming the already named run again makes no call and
/// writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_rerun_over_unchanged_groups_makes_zero_calls(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let map = AtlasMap::Team(c.a);
    build(&pool, &viewer, map, &[team_a_shape(&c)]).await;
    let first_fake = echo();
    let first = name(&pool, &viewer, map, &first_fake).await;
    assert!(first_fake.calls() > 0);
    assert_eq!(first["report"]["failed"], 0, "{first}");
    let named = own_names(&stored(&pool, run_of(&first)).await);
    assert!(named.values().all(Option::is_some));

    build(&pool, &viewer, map, &[team_a_shape(&c)]).await;
    let fake = echo();
    let second = name(&pool, &viewer, map, &fake).await;
    assert_eq!(fake.calls(), 0, "{second}");
    assert_eq!(own_names(&stored(&pool, run_of(&second)).await), named);

    let fake = echo();
    let third = name(&pool, &viewer, map, &fake).await;
    assert_eq!(fake.calls(), 0, "{third}");
    assert_eq!(third["applied"], false, "{third}");
}

/// A changed group triggers exactly one call: one claim joins a theme that is
/// one root leaf in both hierarchies (the same input, so one call names both),
/// while another theme is unchanged and makes none.
#[sqlx::test(migrations = "../../migrations")]
async fn a_changed_group_triggers_exactly_one_call(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let map = AtlasMap::Team(c.a);
    let small = theme(&pool).await;
    let filer = agent(&pool).await;
    let small_claims = claims(&pool, small, filer, ("group", c.a), "S", 5).await;
    let shapes = |extra: &[Uuid]| {
        let s: Vec<Uuid> = small_claims.iter().chain(extra).copied().collect();
        vec![
            team_a_shape(&c),
            Shape {
                theme: small,
                meaning: vec![s.clone()],
                links: vec![s],
            },
        ]
    };
    build(&pool, &viewer, map, &shapes(&[])).await;
    name(&pool, &viewer, map, &echo()).await;

    let new = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, theme_id, embedding) \
         VALUES (gen_random_uuid(), 'A new finding TOKN00 joins the small theme', \
                 decode(md5(random()::text) || md5(random()::text), 'hex'), 0.7, $1, true, \
                 'group', $2, $3, $4::vector) RETURNING id",
    )
    .bind(filer)
    .bind(c.a)
    .bind(small)
    .bind(vector(900, 1))
    .fetch_one(&pool)
    .await
    .unwrap();
    build(&pool, &viewer, map, &shapes(&[new])).await;
    let fake = echo();
    let report = name(&pool, &viewer, map, &fake).await;
    assert_eq!(fake.calls(), 1, "{report} {:?}", fake.prompts());
    assert!(fake.prompts()[0].contains("TOKN00"));
    assert_eq!(report["report"]["shared"], 1, "{report}");
}

/// Every stored document of the named run passes the contract; every
/// repeated name agrees with its group; the run is the new one, keeps the
/// source's params (with `naming` added) and the source's epochs, and is
/// what the serving read returns.
#[sqlx::test(migrations = "../../migrations")]
async fn stored_named_documents_validate_and_agree(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let c = Corpus::new(&pool).await;
    let map = AtlasMap::Team(c.a);
    let source = build(&pool, &viewer, map, &[team_a_shape(&c)]).await;
    // An epoch bump after the build: the named run must still carry the
    // build's epochs, so it is served as stale exactly as its source was.
    sqlx::query("UPDATE claims SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(c.public[5])
        .bind(c.b)
        .execute(&pool)
        .await
        .unwrap();
    let report = name(&pool, &viewer, map, &echo()).await;
    let run = run_of(&report);
    assert_ne!(run, source);

    let levels = stored(&pool, run).await;
    assert_eq!(levels.len(), stored(&pool, source).await.len());
    let names = own_names(&levels);
    for l in &levels {
        let doc = parse_and_validate(l.payload.to_string().as_bytes())
            .unwrap_or_else(|v| panic!("{}: {v}", l.group_id));
        let h = l.hierarchy.clone();
        match doc {
            LevelDocument::Group(g) => {
                assert_eq!(g.run_id, run);
                assert_eq!(g.needs_naming, g.name.is_none());
                for ch in &g.children {
                    assert_eq!(ch.name, names[&(h.clone(), ch.id)]);
                    assert_eq!(ch.needs_naming, ch.name.is_none());
                }
                for b in &g.breadcrumbs {
                    assert_eq!(b.name, names[&(h.clone(), b.level_id)]);
                }
            }
            LevelDocument::Leaf(lf) => {
                assert_eq!(lf.run_id, run);
                assert_eq!(lf.needs_naming, lf.name.is_none());
                for b in &lf.breadcrumbs {
                    assert_eq!(b.name, names[&(h.clone(), b.level_id)]);
                }
            }
        }
    }
    assert!(names.keys().any(|(h, _)| h == "links"));
    assert!(names.values().all(Option::is_some));

    type Epochs = (i64, i64, i64, i64);
    let epochs = |id: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_as::<_, (serde_json::Value, i64, i64, i64, i64)>(
                "SELECT params, map_epoch, public_epoch, map_left_epoch, public_left_epoch \
                   FROM atlas_map_runs WHERE id = $1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    let (sp, a1, b1, c1, d1) = epochs(source).await;
    let (np, a2, b2, c2, d2) = epochs(run).await;
    let e: (Epochs, Epochs) = ((a1, b1, c1, d1), (a2, b2, c2, d2));
    assert_eq!(e.0, e.1, "the named run keeps the source's epochs");
    assert_eq!(np["layout"], sp["layout"], "the W6 record is kept");
    let keys = np["naming"]["keys"].as_object().unwrap();
    assert_eq!(keys.len(), levels.len());

    let root = root_id(map, AtlasHierarchy::Meaning, c.theme);
    let mut conn = pool.acquire().await.unwrap();
    let served = AtlasMapRepository::level_for_viewer(
        &mut conn,
        &viewer,
        map,
        AtlasHierarchy::Meaning,
        root,
    )
    .await
    .unwrap()
    .expect("served");
    assert_eq!(served.run_id, run);
    assert!(!served.current, "stale, as the source run would be");
}

/// The binary refuses a malformed map or budget before it connects anywhere.
#[test]
fn the_binary_refuses_bad_arguments_before_connecting() {
    let bin = env!("CARGO_BIN_EXE_atlas_naming");
    let cases: [(&[&str], &str); 3] = [
        (&["name", "--map", "team:not-a-uuid"], "is not a uuid"),
        (&["name", "--map", "group:x"], "a map is `public`"),
        (
            &["name", "--map", "public", "--max-calls", "0"],
            "--max-calls must be at least 1",
        ),
    ];
    for (args, want) in cases {
        let out = std::process::Command::new(bin)
            .env_clear()
            .arg("--database-url")
            .arg("postgres://nobody@127.0.0.1:1/none")
            .args(args)
            .output()
            .expect("run atlas_naming");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{args:?} succeeded");
        assert!(stderr.contains(want), "{args:?}: {stderr}");
    }
}
