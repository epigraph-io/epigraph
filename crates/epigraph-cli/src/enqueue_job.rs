//! The job an operator hands `enqueue_job`, validated before anything touches
//! the database.
//!
//! A job is the JSON of one [`EpiGraphJob`] (externally tagged, as the `jobs`
//! table stores it), for example
//! `{"ClusterGraph":{"resolution":1.0,"retain_runs":3}}`. [`parse_job`]
//! accepts it only when:
//!
//! * it deserializes into an [`EpiGraphJob`], so an unknown or retired kind
//!   (the k-means `ThemeClusterRebuild`, a misspelling) is refused;
//! * every key of the kind's body is one the kind has, so a stray or
//!   misspelled extra key is refused rather than silently dropped;
//! * its values are ones the drain can run safely: a `ClusterGraph` needs a
//!   finite `resolution` above 0 and a `retain_runs` of at least 1 (the run
//!   garbage-collects all but the newest `retain_runs` runs after inserting
//!   its own, so 0 deletes the run it just built and its neighbourhoods);
//! * it is not one of the privatization kinds. Their authority is the HTTP
//!   dispatch that flips the plan's state and writes the matching
//!   `security_events` row in one transaction (migrations 077 and 119 keep
//!   every other enqueue of them out); a job enqueued here would carry a
//!   dispatcher and correlation id nobody dispatched.
//!
//! The row is then built by [`EpiGraphJob::into_job`], the conversion every
//! enqueuer uses, so the payload written is the typed job re-serialized, not
//! the operator's text.

use epigraph_jobs::{EpiGraphJob, Job};

/// Why a job was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JobRefusal {
    /// Not JSON at all.
    #[error("the job is not JSON: {0}")]
    NotJson(String),
    /// JSON, but not the JSON of an `EpiGraphJob` (unknown or retired kind,
    /// missing or mistyped field).
    #[error("the job is not an EpiGraphJob (unknown or retired kind, or a missing or mistyped field): {0}")]
    NotAJob(String),
    /// A key the kind does not have.
    #[error("the {kind} job has no field {field:?}")]
    UnknownField {
        /// The kind's tag, as written.
        kind: String,
        /// The key it does not have.
        field: String,
    },
    /// A value the drain would run destructively or meaninglessly.
    #[error("the {kind} job's {field} {reason}")]
    OutOfRange {
        /// The kind's tag.
        kind: &'static str,
        /// The offending field.
        field: &'static str,
        /// What the field must be.
        reason: &'static str,
    },
    /// A privatization kind.
    #[error(
        "{0} jobs are enqueued only by their HTTP dispatch, which writes the plan's state and \
         security event in the same transaction; enqueue_job refuses them"
    )]
    Privatization(&'static str),
}

/// Parse and validate the operator's job text (see the module doc).
///
/// # Errors
/// A [`JobRefusal`] naming why the job was refused.
pub fn parse_job(text: &str) -> Result<EpiGraphJob, JobRefusal> {
    let value: serde_json::Value =
        serde_json::from_str(text.trim()).map_err(|e| JobRefusal::NotJson(e.to_string()))?;
    let job: EpiGraphJob =
        serde_json::from_value(value.clone()).map_err(|e| JobRefusal::NotAJob(e.to_string()))?;

    // Every key the operator wrote must survive the round trip. Keys only, not
    // values: `1` and `1.0` are different JSON numbers and the same f64.
    let written = serde_json::to_value(&job).map_err(|e| JobRefusal::NotAJob(e.to_string()))?;
    if let (Some(input), Some(output)) = (value.as_object(), written.as_object()) {
        for (kind, body) in input {
            let known = output.get(kind).and_then(serde_json::Value::as_object);
            if let (Some(body), Some(known)) = (body.as_object(), known) {
                if let Some(field) = body.keys().find(|k| !known.contains_key(*k)) {
                    return Err(JobRefusal::UnknownField {
                        kind: kind.clone(),
                        field: field.clone(),
                    });
                }
            }
        }
    }

    match job {
        EpiGraphJob::ClusterGraph { resolution, .. }
            if !(resolution.is_finite() && resolution > 0.0) =>
        {
            Err(JobRefusal::OutOfRange {
                kind: "ClusterGraph",
                field: "resolution",
                reason: "must be a finite number above 0",
            })
        }
        EpiGraphJob::ClusterGraph { retain_runs: 0, .. } => Err(JobRefusal::OutOfRange {
            kind: "ClusterGraph",
            field: "retain_runs",
            reason: "must be at least 1 (0 garbage-collects the run the job just built)",
        }),
        EpiGraphJob::PrivatizationApply { .. }
        | EpiGraphJob::PrivatizationRevert { .. }
        | EpiGraphJob::PrivatizationReseal { .. } => Err(JobRefusal::Privatization(job.job_type())),
        _ => Ok(job),
    }
}

/// The row the queue writes for `job`: [`EpiGraphJob::into_job`].
///
/// # Errors
/// A [`JobRefusal::NotAJob`] if the job cannot be serialized.
pub fn job_row(job: EpiGraphJob) -> Result<Job, JobRefusal> {
    job.into_job()
        .map_err(|e| JobRefusal::NotAJob(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cluster_graph_job_is_accepted_and_written_as_the_typed_job() {
        let job = parse_job(r#"{"ClusterGraph":{"resolution":1,"retain_runs":3}}"#)
            .expect("a valid ClusterGraph");
        let row = job_row(job).expect("row");
        assert_eq!(row.job_type, "cluster_graph");
        assert_eq!(
            row.payload,
            serde_json::json!({"ClusterGraph": {"resolution": 1.0, "retain_runs": 3}})
        );
    }

    #[test]
    fn a_retired_or_unknown_kind_is_refused() {
        for text in [
            r#"{"ThemeClusterRebuild":{"max_themes":16,"min_claims_per_theme":5,"skip_if_unchanged":true}}"#,
            r#"{"ClusterGrpah":{"resolution":1.0,"retain_runs":3}}"#,
            r#"{"ClusterGraph":{"resolution":1.0}}"#,
            r#"{"ClusterGraph":{"resolution":"high","retain_runs":3}}"#,
            r#"["ClusterGraph"]"#,
            r#""ClusterGraph""#,
        ] {
            assert!(
                matches!(parse_job(text), Err(JobRefusal::NotAJob(_))),
                "{text} must be refused as not a job: {:?}",
                parse_job(text)
            );
        }
        assert!(matches!(parse_job("{"), Err(JobRefusal::NotJson(_))));
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let got =
            parse_job(r#"{"ClusterGraph":{"resolution":1.0,"retain_runs":3,"retian_runs":5}}"#)
                .err();
        assert_eq!(
            got,
            Some(JobRefusal::UnknownField {
                kind: "ClusterGraph".into(),
                field: "retian_runs".into()
            })
        );
    }

    #[test]
    fn a_cluster_graph_the_drain_would_run_destructively_is_refused() {
        for (text, field) in [
            (
                r#"{"ClusterGraph":{"resolution":1.0,"retain_runs":0}}"#,
                "retain_runs",
            ),
            (
                r#"{"ClusterGraph":{"resolution":0,"retain_runs":3}}"#,
                "resolution",
            ),
            (
                r#"{"ClusterGraph":{"resolution":-1.0,"retain_runs":3}}"#,
                "resolution",
            ),
        ] {
            assert!(
                matches!(parse_job(text), Err(JobRefusal::OutOfRange { field: f, .. }) if f == field),
                "{text} must be refused on {field}: {:?}",
                parse_job(text)
            );
        }
        // The boundary values are accepted.
        assert!(parse_job(r#"{"ClusterGraph":{"resolution":0.01,"retain_runs":1}}"#).is_ok());
    }

    #[test]
    fn the_privatization_kinds_are_refused() {
        let ids = r#""plan_id":"00000000-0000-0000-0000-000000000001","dispatched_by":"00000000-0000-0000-0000-000000000002","correlation_id":"c""#;
        for (kind, tag) in [
            ("PrivatizationApply", "privatization_apply"),
            ("PrivatizationRevert", "privatization_revert"),
        ] {
            let text = format!("{{\"{kind}\":{{{ids}}}}}");
            assert_eq!(parse_job(&text).err(), Some(JobRefusal::Privatization(tag)));
        }
        let reseal = r#"{"PrivatizationReseal":{"group_id":"00000000-0000-0000-0000-000000000001","dispatched_by":"00000000-0000-0000-0000-000000000002","correlation_id":"c"}}"#;
        assert!(matches!(
            parse_job(reseal),
            Err(JobRefusal::Privatization(_))
        ));
    }
}
