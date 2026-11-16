//! The box-side halves of the naming step: the reads ([`read_member_texts`],
//! [`read_previous`]) and the operator path [`name_map`], which names a
//! map's latest finished run and stores it as a new run.

use std::collections::BTreeMap;

use anyhow::{ensure, Context};
use epigraph_atlas_contract::{LevelDocument, SCHEMA_VERSION};
use epigraph_db::repos::atlas_map::{AtlasHierarchy, AtlasMap, LevelDoc, NewMapRun};
use epigraph_db::repos::atlas_naming::FinishedRun;
use epigraph_db::{AtlasMapRepository, AtlasMeaningRepository, AtlasNamingRepository, Viewer};
use serde_json::json;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use super::backend::NameBackend;
use super::name::{name_levels, plan_samples, NamingOptions, NamingRecord, Previous, SamplePlan};
use crate::atlas_meaning::tree::map_key;

/// The text of every candidate of `plan` that `map` may draw now, through
/// the map-scoped read W3 and W4 use
/// ([`AtlasMeaningRepository::claim_labels`]: public claims, plus the team's
/// own on a team map). A candidate the map may no longer draw (narrowed, or
/// moved to another team since the documents were built) is absent, so it
/// feeds no name. The documents' own `label` fields are never used.
///
/// # Errors
/// A database error.
pub async fn read_member_texts(
    conn: &mut PgConnection,
    viewer: &Viewer,
    map: AtlasMap,
    plan: &SamplePlan,
) -> anyhow::Result<BTreeMap<Uuid, String>> {
    let ids = plan.claim_ids();
    let mut out = BTreeMap::new();
    for chunk in ids.chunks(5_000) {
        out.extend(AtlasMeaningRepository::claim_labels(conn, viewer, map, chunk).await?);
    }
    Ok(out)
}

/// The names the latest finished run of `map` that carries a naming record
/// may lend (none when no run does).
///
/// # Errors
/// A malformed `params.naming`, or a database error.
pub async fn read_previous(
    conn: &mut PgConnection,
    viewer: &Viewer,
    map: AtlasMap,
) -> anyhow::Result<Previous> {
    let Some(run) = AtlasNamingRepository::latest_finished_run(conn, viewer, map, true).await?
    else {
        return Ok(Previous::none());
    };
    let Some(record) = NamingRecord::from_params(&run.params)? else {
        return Ok(Previous::none());
    };
    let mut names = BTreeMap::new();
    for n in AtlasNamingRepository::run_names(conn, viewer, map, run.id).await? {
        if let (Some(name), false) = (n.name, n.needs_naming) {
            names.insert(format!("{}/{}", n.hierarchy, n.group_id), name);
        }
    }
    Ok(Previous::new(&record, &names))
}

fn hierarchy(s: &str) -> anyhow::Result<AtlasHierarchy> {
    match s {
        "meaning" => Ok(AtlasHierarchy::Meaning),
        "links" => Ok(AtlasHierarchy::Links),
        other => anyhow::bail!("unknown hierarchy {other:?}"),
    }
}

fn set_run_id(doc: &mut LevelDocument, run_id: Uuid) {
    match doc {
        LevelDocument::Group(g) => g.run_id = run_id,
        LevelDocument::Leaf(l) => l.run_id = run_id,
    }
}

/// What [`name_map`] was asked for.
#[derive(Debug, Clone, Copy)]
pub struct NameMapOptions {
    pub map: AtlasMap,
    /// Write the named run. Without it no model is called and nothing is
    /// written: the report says how many levels would be named.
    pub write: bool,
    pub max_calls: Option<usize>,
}

/// What [`read_for_naming`] read: the run to name, its documents, each
/// group's sample candidates and their readable texts, and the names an
/// earlier run may lend.
#[derive(Debug, Clone)]
pub struct NamingInput {
    pub source: FinishedRun,
    pub docs: Vec<LevelDocument>,
    rows: Vec<(AtlasHierarchy, Uuid, Option<Uuid>, Uuid, i32)>,
    pub plan: SamplePlan,
    pub texts: BTreeMap<Uuid, String>,
    pub previous: Previous,
}

/// The read half of [`name_map`]: in one snapshot transaction, ended before
/// it returns, the latest finished run of `map`, its levels, the names an
/// earlier run may lend and the member texts through the map-scoped read.
///
/// # Errors
/// No finished run, a level of another schema version, or a database error.
pub async fn read_for_naming(
    conn: &mut PgConnection,
    viewer: &Viewer,
    map: AtlasMap,
) -> anyhow::Result<NamingInput> {
    let mut tx = conn.begin().await.context("begin the naming read")?;
    AtlasMapRepository::begin_build_snapshot(&mut tx, viewer, map).await?;
    let source = AtlasNamingRepository::latest_finished_run(&mut tx, viewer, map, false)
        .await?
        .context("the map has no finished run to name")?;
    let levels = AtlasNamingRepository::run_levels(&mut tx, viewer, map, source.id).await?;
    let mut rows = Vec::with_capacity(levels.len());
    let mut docs = Vec::with_capacity(levels.len());
    for l in levels {
        ensure!(
            u32::try_from(l.schema_version).ok() == Some(SCHEMA_VERSION),
            "level {} of run {} is schema version {}; this step names version {SCHEMA_VERSION}",
            l.group_id,
            source.id,
            l.schema_version
        );
        let doc: LevelDocument = serde_json::from_value(l.payload.clone()).with_context(|| {
            format!(
                "level {} of run {} is not a v1 document",
                l.group_id, source.id
            )
        })?;
        docs.push(doc);
        rows.push((
            hierarchy(&l.hierarchy)?,
            l.group_id,
            l.parent_group_id,
            l.theme_id,
            l.level,
        ));
    }
    let previous = read_previous(&mut tx, viewer, map).await?;
    let plan = plan_samples(&docs)?;
    let texts = read_member_texts(&mut tx, viewer, map, &plan).await?;
    tx.rollback().await.context("end the naming read")?;
    Ok(NamingInput {
        source,
        docs,
        rows,
        plan,
        texts,
        previous,
    })
}

/// Name the latest finished run of `opts.map` and, with `opts.write`, store
/// it as a NEW finished run (a finished run cannot be changed): every level
/// of both hierarchies copied with its `run_id` rewritten and its names
/// filled, the source run's `params` kept whole with the naming record added
/// under `naming`, and the SOURCE run's epochs, because the documents
/// describe that run's snapshot.
///
/// Three steps, and no transaction is open while the model runs: one read
/// transaction ([`read_for_naming`]), then the naming, then one write
/// transaction ([`name_and_write`]). When every name was copied and the
/// source already carries the same record, nothing is written.
///
/// # Errors
/// What [`read_for_naming`] or [`name_and_write`] refuses.
pub async fn name_map(
    conn: &mut PgConnection,
    viewer: &Viewer,
    backend: &dyn NameBackend,
    opts: NameMapOptions,
) -> anyhow::Result<serde_json::Value> {
    let input = read_for_naming(conn, viewer, opts.map).await?;
    name_and_write(conn, viewer, backend, input, opts).await
}

/// The naming and the write half of [`name_map`]. The write refuses when
/// the map's latest finished run is no longer the one that was read: a
/// build that finished while the model ran is newer, and a copy of the older
/// run, finished after it, would be served in its place. The check and the
/// write run under the map's publish lock
/// (`AtlasMapRepository::lock_map_for_publish`), which the nightly takes too.
///
/// # Errors
/// A newer run of the map, documents the contract refuses, or a database
/// error.
pub async fn name_and_write(
    conn: &mut PgConnection,
    viewer: &Viewer,
    backend: &dyn NameBackend,
    input: NamingInput,
    opts: NameMapOptions,
) -> anyhow::Result<serde_json::Value> {
    let map = opts.map;
    let NamingInput {
        source,
        mut docs,
        rows,
        plan,
        texts,
        previous,
    } = input;
    let (record, report) = name_levels(
        &mut docs,
        &plan,
        &texts,
        &previous,
        backend,
        NamingOptions {
            max_calls: opts.max_calls,
            call_model: opts.write,
        },
    )?;
    let mut out = json!({
        "map": map_key(map),
        "source_run_id": source.id,
        "levels": docs.len(),
        "named_levels": record.keys.len(),
        "report": report,
        "applied": false,
    });
    if !opts.write {
        return Ok(out);
    }
    let unchanged =
        NamingRecord::from_params(&source.params)?.as_ref() == Some(&record) && report.calls == 0;
    if unchanged {
        out["note"] = json!("every name was copied and the source run already holds them");
        return Ok(out);
    }

    let mut params = source.params.clone();
    if !params.is_object() {
        params = json!({});
    }
    params["naming"] = serde_json::to_value(&record)?;
    params["named_from_run"] = json!(source.id);
    let mut tx = conn.begin().await.context("begin the naming write")?;
    // The nightly (W9) publishes the same map; both take the map's publish
    // lock before their newer-run check, so a check and a publish cannot
    // interleave with the other's.
    AtlasMapRepository::lock_map_for_publish(&mut tx, map).await?;
    let latest = AtlasNamingRepository::latest_finished_run(&mut tx, viewer, map, false)
        .await?
        .map(|r| r.id);
    ensure!(
        latest == Some(source.id),
        "a newer run of map {} was published since the read (latest {latest:?}, read {}); \
         nothing was written, rerun to name the newer run",
        map_key(map),
        source.id
    );
    let run_id = AtlasMapRepository::write_run(
        &mut tx,
        &NewMapRun {
            map,
            algo: source.algo.clone(),
            params,
            epochs: source.epochs,
        },
    )
    .await?;
    for (doc, (h, group_id, parent, theme_id, level)) in docs.iter_mut().zip(&rows) {
        set_run_id(doc, run_id);
        let body = doc
            .to_stored_json()
            .map_err(|v| anyhow::anyhow!("level {group_id} breaks the contract: {v}"))?;
        AtlasMapRepository::put_level(
            &mut tx,
            run_id,
            &LevelDoc {
                hierarchy: *h,
                group_id: *group_id,
                parent_group_id: *parent,
                theme_id: *theme_id,
                level: *level,
                schema_version: i32::try_from(SCHEMA_VERSION)?,
                payload: serde_json::from_slice(&body)?,
            },
        )
        .await?;
    }
    AtlasMapRepository::finish_run(&mut tx, run_id).await?;
    tx.commit().await.context("commit the named run")?;
    out["applied"] = json!(true);
    out["run_id"] = json!(run_id);
    Ok(out)
}
