//! The mode check every CLI wave bin runs before a writing run (SPEC §10.2,
//! flip runbook).
//!
//! Every belief-mode flag is read once, at startup, by each process that
//! reads it ([`epigraph_engine::belief_modes::current`]). A flag flip is therefore a
//! restart window: an operator shell whose environment was not updated, or was
//! updated before the servers were restarted, starts a wave bin that would
//! write under a different fold from the one the API serves. So before a
//! WRITING run, a wave bin reads the API's `/health` → `belief_modes` and
//! refuses when any mode differs from its own.
//!
//! The check fails closed. A writing run refuses when it cannot read the
//! server's modes at all: nothing listening, a non-2xx answer, a server built
//! before `/health` reported `belief_modes`, or a report this build cannot
//! parse (a mode it does not know). Agreement has to be shown; it is never
//! assumed.
//!
//! A run that writes nothing (`--dry-run`, including `--dry-run --target-fold
//! <mode>`) is exempt and does not contact the API, so a wave can be reviewed
//! under the fold the server will flip to before the flip (SPEC §10.3).
//!
//! `--allow-mode-skew` turns a refusal into a loud warning. It is hidden from
//! `--help` and exists for tests and for a deliberate, recorded operator
//! override; a wave run never needs it.
//!
//! Wave bins wired today: `recompute_betp`, `backfill_factors`, and
//! `decompose_claims` in its two retarget writing modes. A wave bin added
//! later (`attribute_atoms`, `rekey_self_assertions`) calls [`enforce`] the
//! same way.

use std::time::Duration;

use epigraph_engine::belief_modes::{AtomFold, BeliefModes, UnrecognisedFlag};

/// The exit status of a run the mode check refused, distinct from a run that
/// failed for any other reason.
pub const MODE_CHECK_REFUSED_EXIT: i32 = 3;

/// How long the check waits for `/health`.
const HEALTH_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether a run can write. Only a writing run is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunIntent {
    /// The run may write claims, BBAs, factors or edges.
    Writes,
    /// The run writes nothing (a dry run).
    WritesNothing,
}

/// API base precedence: `EPIGRAPH_API` (explicit override) first,
/// `EPIGRAPH_API_URL` (the container-standard name) second,
/// `http://127.0.0.1:8080` otherwise. Takes already-read env values so it is a
/// pure function; set-but-empty values are treated as absent.
#[must_use]
pub fn resolve_api_base(epigraph_api: Option<String>, epigraph_api_url: Option<String>) -> String {
    let non_empty = |v: Option<String>| v.filter(|s| !s.is_empty());
    non_empty(epigraph_api)
        .or_else(|| non_empty(epigraph_api_url))
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string())
}

/// Read the server's belief modes from `{api_base}/health`.
///
/// # Errors
/// A description of why the modes could not be read: the request failed, the
/// status was not 2xx, the body was not JSON, it carried no `belief_modes`, or
/// its `belief_modes` is not exactly the set this build knows.
pub async fn fetch_server_modes(
    http: &reqwest::Client,
    api_base: &str,
) -> Result<BeliefModes, String> {
    let url = format!("{}/health", api_base.trim_end_matches('/'));
    let response = http
        .get(&url)
        .timeout(HEALTH_TIMEOUT)
        .send()
        .await
        .map_err(|e| format!("GET {url} failed: {e}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("GET {url} answered {status}"));
    }
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("GET {url} did not return JSON: {e}"))?;
    let Some(reported) = body.get("belief_modes") else {
        return Err(format!(
            "GET {url} reports no belief_modes (a server built before it reported its modes)"
        ));
    };
    serde_json::from_value(reported.clone()).map_err(|e| {
        format!("GET {url} reports belief_modes this build cannot compare ({e}): {reported}")
    })
}

/// The decision for a WRITING run, given this process's modes, the flags it
/// read but did not recognise, and what the server reported (or why it could
/// not be read). Pure.
///
/// # Errors
/// The refusal text: every differing mode with both values, or why the
/// server's modes could not be read; then every unrecognised flag of this
/// process, since a typo that fell back to the default is the likeliest
/// cause of a skew.
pub fn check_writing_run(
    bin: &str,
    ours: &BeliefModes,
    unrecognised: &[UnrecognisedFlag],
    server: Result<BeliefModes, String>,
    api_base: &str,
) -> Result<(), String> {
    let typos: String = unrecognised
        .iter()
        .map(|flag| format!("\nNote: {flag}."))
        .collect();
    let theirs = server.map_err(|why| {
        format!(
            "{bin}: refusing a writing run: cannot read the API's belief_modes ({why}). \
             A writing run must show that its belief modes match the API's (SPEC §10.2). \
             Checked {api_base}: set EPIGRAPH_API (or EPIGRAPH_API_URL) to the API this run \
             writes alongside, or run with --dry-run.{typos}"
        )
    })?;
    let skew = ours.skew(&theirs);
    if skew.is_empty() {
        return Ok(());
    }
    let lines: Vec<String> = skew.iter().map(|s| format!("  {s}")).collect();
    Err(format!(
        "{bin}: refusing a writing run: this process's belief modes differ from the API's at \
         {api_base} (SPEC §10.2):\n{}\n\
         Start this run with the server's modes, or run with --dry-run.{typos}",
        lines.join("\n")
    ))
}

/// Run the mode check for `bin` and its `intent`, reading this process's
/// modes and the API base from the environment.
///
/// A run that writes nothing returns `Ok` without contacting the API. With
/// `allow_skew`, a refusal is printed as a warning and the run proceeds.
///
/// # Errors
/// The refusal text; the caller prints it and exits with
/// [`MODE_CHECK_REFUSED_EXIT`].
pub async fn enforce(bin: &str, intent: RunIntent, allow_skew: bool) -> Result<(), String> {
    // Every run reports a typo'd flag of its own, dry runs included: a CLI bin
    // may install no log subscriber, so stderr is where the operator sees it.
    let unrecognised = epigraph_engine::belief_modes::unrecognised();
    for flag in unrecognised {
        eprintln!("WARNING: {bin}: belief-mode flag ignored: {flag}");
    }
    if intent == RunIntent::WritesNothing {
        return Ok(());
    }
    let api_base = resolve_api_base(
        std::env::var("EPIGRAPH_API").ok(),
        std::env::var("EPIGRAPH_API_URL").ok(),
    );
    let server = fetch_server_modes(&reqwest::Client::new(), &api_base).await;
    let ours = epigraph_engine::belief_modes::current();
    match check_writing_run(bin, ours, unrecognised, server, &api_base) {
        Ok(()) => Ok(()),
        Err(refusal) if allow_skew => {
            eprintln!("WARNING: --allow-mode-skew: proceeding despite:\n{refusal}");
            Ok(())
        }
        Err(refusal) => Err(refusal),
    }
}

/// [`enforce`], then exit with [`MODE_CHECK_REFUSED_EXIT`] on a refusal. For a
/// bin's `main`, before it opens the database.
pub async fn enforce_or_exit(bin: &str, intent: RunIntent, allow_skew: bool) {
    if let Err(refusal) = enforce(bin, intent, allow_skew).await {
        eprintln!("{refusal}");
        std::process::exit(MODE_CHECK_REFUSED_EXIT);
    }
}

/// The decision for a WRITING run of a bin whose writes fold atom caches, given
/// this process's modes. Pure.
///
/// The cache writers in this build implement only the legacy fold. The mode
/// check compares flag VALUES with the API's, not what either build can do,
/// so a binary older than the server's fold would pass it and write
/// legacy-fold caches while another fold is in force. That is refused here,
/// whatever the server reports. The change that adds a fold to these writers
/// widens this check.
///
/// # Errors
/// The refusal text, when `ours.atom_fold` is not the legacy fold.
pub fn check_build_writes_fold(bin: &str, ours: &BeliefModes) -> Result<(), String> {
    if ours.atom_fold == AtomFold::Legacy {
        return Ok(());
    }
    Err(format!(
        "{bin}: refusing a writing run: this process runs atom_fold={fold} (set by {env}), but \
         this build writes only the legacy fold, so it would write legacy-fold caches while \
         the {fold} fold is in force. Run a build that implements the {fold} fold, or run \
         with --dry-run. --allow-mode-skew does not lift this.",
        fold = ours.atom_fold,
        env = AtomFold::ENV,
    ))
}

/// [`check_build_writes_fold`] for this process, then exit with
/// [`MODE_CHECK_REFUSED_EXIT`] on a refusal. A run that writes nothing is
/// exempt. For the `main` of a bin whose writes fold atom caches, after
/// [`enforce_or_exit`] (so a skew is reported as a skew) and before it opens
/// the database.
pub fn enforce_build_fold_or_exit(bin: &str, intent: RunIntent) {
    if intent == RunIntent::WritesNothing {
        return;
    }
    if let Err(refusal) = check_build_writes_fold(bin, epigraph_engine::belief_modes::current()) {
        eprintln!("{refusal}");
        std::process::exit(MODE_CHECK_REFUSED_EXIT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_engine::belief_modes::{BpApply, CompoundWriteGuard};

    /// Only the legacy fold passes, whatever the other modes are; every other
    /// fold is refused, named, with what this build writes.
    #[test]
    fn a_fold_this_build_cannot_write_is_refused_and_legacy_is_not() {
        for fold in AtomFold::ALL.iter().copied() {
            let ours = BeliefModes {
                atom_fold: fold,
                bp_apply: BpApply::On,
                ..BeliefModes::default()
            };
            let decision = check_build_writes_fold("bin", &ours);
            if fold == AtomFold::Legacy {
                assert_eq!(decision, Ok(()));
            } else {
                let refusal = decision.unwrap_err();
                assert!(
                    refusal.contains(&format!("atom_fold={fold}"))
                        && refusal.contains("writes only the legacy fold"),
                    "{refusal}"
                );
            }
        }
    }

    #[test]
    fn matching_modes_pass_and_any_difference_refuses_naming_every_differing_mode() {
        let server = BeliefModes::default();
        assert_eq!(
            check_writing_run("bin", &server, &[], Ok(server), "http://api"),
            Ok(())
        );

        let ours = BeliefModes {
            atom_fold: AtomFold::Aef,
            compound_write_guard: CompoundWriteGuard::Refuse,
            ..server
        };
        let refusal = check_writing_run("bin", &ours, &[], Ok(server), "http://api").unwrap_err();
        for needle in [
            "atom_fold",
            "aef",
            "legacy",
            "EPIGRAPH_ATOM_FOLD",
            "compound_write_guard",
            "refuse",
            "warn",
        ] {
            assert!(refusal.contains(needle), "{needle:?} in {refusal}");
        }
        // A mode that agrees is not named.
        assert!(!refusal.contains("bp_apply"), "{refusal}");

        // One differing mode is enough, whichever it is.
        let only_bp = BeliefModes {
            bp_apply: BpApply::On,
            ..server
        };
        assert!(check_writing_run("bin", &only_bp, &[], Ok(server), "http://api").is_err());
    }

    #[test]
    fn unreadable_server_modes_refuse_a_writing_run() {
        let ours = BeliefModes::default();
        let refusal = check_writing_run(
            "bin",
            &ours,
            &[],
            Err("GET http://api/health failed: connection refused".into()),
            "http://api",
        )
        .unwrap_err();
        assert!(refusal.contains("belief_modes"), "{refusal}");
        assert!(refusal.contains("connection refused"), "{refusal}");
    }

    /// A typo'd flag of this process is named in either refusal, with the
    /// value as typed and the default it fell back to; a matching run is not
    /// refused because of it.
    #[test]
    fn a_refusal_names_every_unrecognised_flag_of_this_process() {
        let read = BeliefModes::from_lookup(|key| {
            (key == AtomFold::ENV).then(|| "aef-standalone".to_string())
        });
        let server = BeliefModes {
            atom_fold: AtomFold::AefStandalone,
            ..BeliefModes::default()
        };
        for refusal in [
            check_writing_run(
                "bin",
                &read.modes,
                &read.unrecognised,
                Ok(server),
                "http://api",
            )
            .unwrap_err(),
            check_writing_run(
                "bin",
                &read.modes,
                &read.unrecognised,
                Err("unreachable".into()),
                "http://api",
            )
            .unwrap_err(),
        ] {
            assert!(
                refusal.contains("EPIGRAPH_ATOM_FOLD=\"aef-standalone\"")
                    && refusal.contains("runs legacy"),
                "{refusal}"
            );
        }
        assert_eq!(
            check_writing_run(
                "bin",
                &read.modes,
                &read.unrecognised,
                Ok(BeliefModes::default()),
                "http://api"
            ),
            Ok(())
        );
    }

    #[test]
    fn api_base_prefers_epigraph_api_then_epigraph_api_url_and_ignores_empty() {
        assert_eq!(
            resolve_api_base(Some("http://a".into()), Some("http://b".into())),
            "http://a"
        );
        assert_eq!(
            resolve_api_base(Some(String::new()), Some("http://b".into())),
            "http://b"
        );
        assert_eq!(resolve_api_base(None, None), "http://127.0.0.1:8080");
    }
}
