//! The scheduled `theme_cluster_rebuild` job ran only the retired k-means
//! prototype (`epigraph_engine::theme_kmeans`), so the job kind is gone
//! (backlog a0ed0180, operator ruling R-29 as revised). Its payload no longer
//! names an [`EpiGraphJob`]; a sibling job still does (calibration).

use epigraph_jobs::EpiGraphJob;

#[test]
fn the_theme_rebuild_job_kind_no_longer_exists() {
    let sibling = serde_json::json!({
        "ClusterGraph": { "resolution": 1.0, "retain_runs": 3 }
    });
    let job: EpiGraphJob = serde_json::from_value(sibling).expect("calibration: ClusterGraph");
    assert_eq!(job.job_type(), "cluster_graph");

    let retired = serde_json::json!({
        "ThemeClusterRebuild": {
            "max_themes": 16,
            "min_claims_per_theme": 5,
            "skip_if_unchanged": true
        }
    });
    let parsed = serde_json::from_value::<EpiGraphJob>(retired);
    assert!(
        parsed.is_err(),
        "ThemeClusterRebuild must not deserialize into a job: {parsed:?}"
    );
}
