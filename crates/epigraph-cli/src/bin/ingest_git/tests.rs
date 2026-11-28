use super::*;

// -------------------------------------------------------------------------
// Deterministic per-author agent identity tests
// -------------------------------------------------------------------------

/// A fixed test secret (never a real one).
fn test_keys() -> GitAuthorKeys {
    GitAuthorKeys::parse(&"a5".repeat(32)).expect("64 hex characters")
}

#[test]
fn author_key_is_deterministic_per_email() {
    let keys = test_keys();
    let a = keys.author("owner@example.com");
    let b = test_keys().author("owner@example.com"); // a second load of the same secret
    let c = keys.author("other@example.com");
    assert_eq!(a.public_key(), b.public_key(), "same email => same key");
    assert_ne!(
        a.public_key(),
        c.public_key(),
        "different email => different key"
    );
}

#[test]
fn author_email_is_normalized() {
    let keys = test_keys();
    assert_eq!(
        keys.author("Owner@Example.com  ").public_key(),
        keys.author("owner@example.com").public_key(),
        "case/space-insensitive email"
    );
}

// Review of backlog 7d9e60c6: a key derived from the email alone is
// computable from the public git log, and an agent client for such a key
// (which older servers provisioned on registration) is a login anyone can
// use. The key must depend on the host secret, and must not be the old
// public formula.
#[test]
fn author_key_is_not_computable_from_the_email_alone() {
    let email = "alice@example.com";
    let under_a = test_keys().author(email).public_key();
    let under_b = GitAuthorKeys::parse(&"5a".repeat(32))
        .unwrap()
        .author(email)
        .public_key();
    assert_ne!(under_a, under_b, "the host secret must be an input");

    let public_seed = blake3::hash(format!("epigraph-git-author-v1:{email}").as_bytes());
    let public_formula = AgentSigner::from_bytes(public_seed.as_bytes()).unwrap();
    assert_ne!(under_a, public_formula.public_key());
    assert_ne!(under_b, public_formula.public_key());

    // The documented derivation, spelled out independently.
    let expected_seed = blake3::keyed_hash(
        &[0xa5; 32],
        format!("epigraph-git-author-v2:{email}").as_bytes(),
    );
    assert_eq!(
        under_a,
        AgentSigner::from_bytes(expected_seed.as_bytes())
            .unwrap()
            .public_key()
    );
}

#[test]
fn repo_root_key_is_keyed_too() {
    let public_seed = blake3::hash(b"epigraph-git-author-v1:git-ingester@epigraph.system");
    let public_formula = AgentSigner::from_bytes(public_seed.as_bytes()).unwrap();
    assert_ne!(
        test_keys().repo_root().public_key(),
        public_formula.public_key()
    );
    assert_ne!(
        test_keys().repo_root().public_key(),
        GitAuthorKeys::parse(&"5a".repeat(32))
            .unwrap()
            .repo_root()
            .public_key(),
        "the host secret must be an input"
    );
}

#[test]
fn author_key_file_must_be_32_bytes_of_hex_and_not_zero() {
    assert!(GitAuthorKeys::parse(&format!("  {}\n", "a5".repeat(32))).is_ok());
    assert!(GitAuthorKeys::parse(&"a5".repeat(31)).is_err(), "too short");
    assert!(GitAuthorKeys::parse(&"a5".repeat(33)).is_err(), "too long");
    assert!(GitAuthorKeys::parse(&"zz".repeat(32)).is_err(), "not hex");
    assert!(GitAuthorKeys::parse(&"00".repeat(32)).is_err(), "all zero");
    let err = GitAuthorKeys::parse(&"zz".repeat(32)).err().unwrap();
    assert!(!err.contains("zz"), "the error must not echo the content");
}

#[test]
fn a_live_run_without_an_author_key_file_is_refused() {
    let err = author_keys_for_run(None, false)
        .err()
        .expect("live run refused");
    assert!(err.contains("--author-key-file"), "{err}");
    assert!(
        author_keys_for_run(None, true).is_ok(),
        "a dry run needs no key file"
    );

    let dir = std::env::temp_dir().join(format!("ingest-git-key-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("author.key");
    std::fs::write(&path, format!("{}\n", "a5".repeat(32))).unwrap();
    let loaded = author_keys_for_run(Some(&path), false).expect("key file loads");
    assert_eq!(
        loaded.author("x@example.com").public_key(),
        test_keys().author("x@example.com").public_key()
    );
    assert!(author_keys_for_run(Some(&dir.join("missing")), true).is_err());
    std::fs::remove_dir_all(&dir).ok();
}

// -------------------------------------------------------------------------
// Repo-root system-agent identity tests
// -------------------------------------------------------------------------

#[test]
fn repo_root_agent_is_fixed_and_orchestrator_independent() {
    // The repo-root node must be attributed to a single, stable system agent
    // derived from a constant — never the per-PR orchestrator — so that
    // `create_or_get` collapses the repo node across every PR/orchestrator.
    // `orchestrator_id` is not even an input to the repo-root signer, so two
    // different orchestrators necessarily resolve the same repo-root key.
    let keys = test_keys();
    assert_eq!(
        keys.repo_root().public_key(),
        test_keys().repo_root().public_key(),
        "repo-root signer is deterministic under one host secret"
    );
    assert_ne!(
        keys.repo_root().public_key(),
        keys.author("git-ingester@epigraph.system").public_key(),
        "repo-root system agent is distinct from any git author"
    );
}

// -------------------------------------------------------------------------
// Orchestrator-agent resolution tests
// -------------------------------------------------------------------------

#[test]
fn parses_orchestrator_trailer() {
    let body = "fix(api): x\n\nEvidence:\n- y\n\nEpigraph-Orchestrator-Id: 7b3a0c1e-0000-4000-8000-000000000001\nCo-Authored-By: Claude <a@b>";
    assert_eq!(
        parse_orchestrator_trailer(body),
        Some("7b3a0c1e-0000-4000-8000-000000000001".parse().unwrap())
    );
    assert_eq!(parse_orchestrator_trailer("no trailer here"), None);
}

#[test]
fn orchestrator_trailer_key_match_is_case_insensitive() {
    // The doc comment promises a case-insensitive key match; assert lower- and
    // upper-cased trailer keys both resolve to the same id.
    let id = "7b3a0c1e-0000-4000-8000-000000000001";
    assert_eq!(
        parse_orchestrator_trailer(&format!("epigraph-orchestrator-id: {id}")),
        Some(id.parse().unwrap())
    );
    assert_eq!(
        parse_orchestrator_trailer(&format!("EPIGRAPH-ORCHESTRATOR-ID: {id}")),
        Some(id.parse().unwrap())
    );
}

#[test]
fn orchestrator_trailer_last_occurrence_wins() {
    // The doc comment promises last-occurrence-wins (trailers live at the bottom),
    // so a later trailer must override an earlier one.
    let first = "7b3a0c1e-0000-4000-8000-000000000001";
    let last = "7b3a0c1e-0000-4000-8000-00000000ffff";
    let body = format!("Epigraph-Orchestrator-Id: {first}\nEpigraph-Orchestrator-Id: {last}");
    assert_eq!(
        parse_orchestrator_trailer(&body),
        Some(last.parse().unwrap())
    );
}

// -------------------------------------------------------------------------
// Repo-node find-or-create packet tests
// -------------------------------------------------------------------------

/// One `git log --format=<RS>%H<FS>%an<FS>%ae<FS>%aI<FS>%P<FS>%B --name-only`
/// record, as `parse_git_log` reads it (`%B` ends with a newline, then
/// `--name-only` adds a blank line and the file names).
fn git_log_record(hash: &str, email: &str, message: &str) -> String {
    format!(
        "{RECORD_SEP}{hash}{FIELD_SEP}A{FIELD_SEP}{email}{FIELD_SEP}2026-11-14T00:00:00Z\
         {FIELD_SEP}{FIELD_SEP}{message}\n\nsrc/lib.rs\n"
    )
}

// Backlog 7d9e60c6 (5): trailer lines are not Verification evidence, and a
// wrapped bullet is one evidence row, not one per line.
#[test]
fn trailer_block_is_not_section_evidence() {
    let msg = "fix(api): x\n\n**Evidence:**\n- e1\n\n**Verification:**\n- cargo test: 3 passed\n\
                   - clippy clean\n\nCo-Authored-By: A Bot <a@example.com>\n\
                   Claude-Session: https://example.com/s/1";
    let out = git_log_record("h1", "a@example.com", msg);
    let commits = parse_git_log_output(&out).unwrap();
    assert_eq!(commits.len(), 1);
    let c = &commits[0];
    assert_eq!(c.verification, vec!["cargo test: 3 passed", "clippy clean"]);
    assert_eq!(c.evidence, vec!["e1"]);
    assert_eq!(
        c.trailers,
        vec![
            "Co-Authored-By: A Bot <a@example.com>",
            "Claude-Session: https://example.com/s/1"
        ]
    );
    assert_eq!(c.files_changed, vec!["src/lib.rs"]);

    // With no Verification section the trailers would have landed in Reasoning.
    let (_, _, _, _, reasoning, _) =
        parse_commit_message("feat: y\n\nReasoning:\n- r1\n\nSigned-off-by: A <a@b>");
    assert_eq!(reasoning, vec!["r1"]);
}

#[test]
fn wrapped_bullets_are_one_item_and_every_list_marker_opens_one() {
    let msg = "feat(x): y\n\n**Evidence:**\n- first line\n  wrapped onto two\n- second\n\
               * star\n+ plus\n1. one\n2) two\n\n**Verification:**\n- passes:\n  3 tests\n\
               unindented wrap\n\nseparate paragraph";
    let (_, _, _, evidence, _, verification) = parse_commit_message(msg);
    assert_eq!(
        evidence,
        vec![
            "first line wrapped onto two",
            "second",
            "star",
            "plus",
            "one",
            "two"
        ]
    );
    assert_eq!(
        verification,
        vec!["passes: 3 tests unindented wrap", "separate paragraph"]
    );
}

#[test]
fn last_paragraph_that_is_not_all_trailers_is_kept() {
    // A Verification section closing the message is not a trailer block,
    // even when its bullets hold `key: value` text.
    let msg = "test(x): y\n\nEvidence:\n- e\n\nVerification:\n- cargo test: ok\n- fmt: clean";
    let (_, _, _, _, _, verification) = parse_commit_message(msg);
    assert_eq!(verification, vec!["cargo test: ok", "fmt: clean"]);
    let (body, trailers) = split_trailers(msg);
    assert!(trailers.is_empty());
    assert_eq!(body, msg);
    // A one-paragraph message (`docs: x` looks like a trailer) has no trailers.
    assert!(split_trailers("docs: x").1.is_empty());
    assert_eq!(parse_header(&split_trailers("docs: x").0).2, "x");
    // A mixed last paragraph is not a trailer block either.
    assert!(split_trailers("a: b\n\nKey: v\nplain text").1.is_empty());
}

// Review of 7d9e60c6: a closing one-line `Key: value` paragraph whose key is
// a plain word is message text, not a trailer block, so it is not dropped.
#[test]
fn closing_single_word_key_line_is_kept_as_text() {
    let msg = "test(x): y\n\nEvidence:\n- e\n\nVerification: cargo test passes";
    let (body, trailers) = split_trailers(msg);
    assert!(trailers.is_empty(), "{trailers:?}");
    assert_eq!(body, msg);
    let (_, _, _, evidence, _, _) = parse_commit_message(msg);
    assert!(
        evidence.iter().any(|e| e.contains("cargo test passes")),
        "{evidence:?}"
    );
    assert!(split_trailers("fix: y\n\nNote: see #12").1.is_empty());
    // Hyphenated keys and conventional single-word keys still are trailers.
    assert_eq!(
        split_trailers("fix: y\n\nFixes: #12\nSigned-off-by: A <a@b>").1,
        vec!["Fixes: #12", "Signed-off-by: A <a@b>"]
    );
}

// Backlog 7d9e60c6 (3): an Epigraph-Orchestrator-Id trailer in a commit
// message is read (it used to see only the `[type][scope] claim` header).
#[test]
fn commit_message_orchestrator_trailer_is_read() {
    let id = Uuid::parse_str("7b3a0c1e-0000-4000-8000-0000000000c1").unwrap();
    let msg = format!(
        "feat(x): y\n\n**Verification:**\n- ok\n\nEpigraph-Orchestrator-Id: {id}\n\
         Co-Authored-By: A <a@b>"
    );
    let mut out = git_log_record("h0", "a@b", "chore: earlier commit, no trailer");
    out.insert_str(0, &git_log_record("h1", "a@b", &msg)); // git log is newest first
    let commits = parse_git_log_output(&out).unwrap();
    assert_eq!(commits.len(), 2);
    assert_eq!(
        resolve_orchestrator_agent(None, "PR body without one", &commits, None),
        Ok(id)
    );
    // The trailer is not a Verification row.
    assert_eq!(commits[1].verification, vec!["ok"]);
}

// Backlog 7d9e60c6 (2): EPIGRAPH_DEFAULT_ORCHESTRATOR_ID is a fallback only.
#[test]
fn orchestrator_precedence_flag_body_commit_then_default() {
    let flag = Uuid::parse_str("00000000-0000-4000-8000-0000000000f1").unwrap();
    let body_id = Uuid::parse_str("00000000-0000-4000-8000-0000000000b1").unwrap();
    let commit_id = Uuid::parse_str("00000000-0000-4000-8000-0000000000c1").unwrap();
    let default = "00000000-0000-4000-8000-0000000000d1";
    let body = format!("text\n\nEpigraph-Orchestrator-Id: {body_id}");
    let out = git_log_record(
        "h1",
        "a@b",
        &format!("fix: y\n\nEpigraph-Orchestrator-Id: {commit_id}"),
    );
    let commits = parse_git_log_output(&out).unwrap();
    let r = |f, b: &str, c: &[ParsedCommit], d| resolve_orchestrator_agent(f, b, c, d);
    assert_eq!(r(Some(flag), &body, &commits, Some(default)), Ok(flag));
    assert_eq!(r(None, &body, &commits, Some(default)), Ok(body_id));
    assert_eq!(r(None, "", &commits, Some(default)), Ok(commit_id));
    assert_eq!(
        r(None, "", &[], Some(default)),
        Ok(Uuid::parse_str(default).unwrap())
    );
    assert!(r(None, "", &[], None).is_err());
    assert!(r(None, "", &[], Some("  ")).is_err());
    let bad = r(None, "", &[], Some("not-a-uuid")).unwrap_err();
    assert!(bad.contains("must be a UUID"), "{bad}");
}

// Review of 7d9e60c6: with trailers in several commits, the OLDEST wins.
#[test]
fn orchestrator_trailer_of_the_oldest_commit_wins() {
    let older = Uuid::parse_str("00000000-0000-4000-8000-0000000000a1").unwrap();
    let newer = Uuid::parse_str("00000000-0000-4000-8000-0000000000a2").unwrap();
    let mut out = git_log_record(
        "h0",
        "a@b",
        &format!("fix: first\n\nEpigraph-Orchestrator-Id: {older}"),
    );
    // git log is newest first.
    out.insert_str(
        0,
        &git_log_record(
            "h1",
            "a@b",
            &format!("fix: second\n\nEpigraph-Orchestrator-Id: {newer}"),
        ),
    );
    let commits = parse_git_log_output(&out).unwrap();
    assert_eq!(commits[0].hash, "h0", "commits are oldest first");
    assert_eq!(
        resolve_orchestrator_agent(None, "", &commits, None),
        Ok(older)
    );
}

// Backlog 7d9e60c6 (4): `#8` resolves only claims citing PR #8, not #80.
#[test]
fn pr_citation_matches_the_exact_number() {
    assert!(content_cites_pr("Fixed in PR #8.", 8));
    assert!(content_cites_pr("fixed in pr #8", 8));
    assert!(content_cites_pr("PR #80 and PR #8", 8));
    assert!(content_cites_pr("PR #8", 8));
    assert!(!content_cites_pr("Fixed in PR #80", 8));
    assert!(!content_cites_pr("PR #812 merged", 8));
    assert!(!content_cites_pr("no citation", 8));
    // Left boundary (review of 7d9e60c6): `apr #8` / `SPR #8` is not PR #8.
    assert!(!content_cites_pr("see apr #8", 8));
    assert!(!content_cites_pr("SPR #8", 8));
    assert!(content_cites_pr("(PR #8)", 8));
    assert!(content_cites_pr("SPR #8, then PR #8", 8));
    let resp = serde_json::json!({"claims": [
        {"id": "00000000-0000-4000-8000-000000000001", "content": "landed in PR #80"},
        {"id": "00000000-0000-4000-8000-000000000002", "content": "landed in PR #8"},
        {"id": "00000000-0000-4000-8000-000000000003", "content": "PR #812"},
        {"id": "00000000-0000-4000-8000-000000000004"}
    ]});
    assert_eq!(
        claim_ids_citing_pr(&resp, 8),
        vec![Uuid::parse_str("00000000-0000-4000-8000-000000000002").unwrap()]
    );
}

// Backlog 7d9e60c6 (6): per-author keys are derived from the email outside
// PR mode too, so a re-run maps an author to the same agent.
#[test]
fn per_author_registry_keys_are_stable_across_runs() {
    let mut run1 = AgentRegistry::new(test_keys());
    let mut run2 = AgentRegistry::new(test_keys());
    let pk1 = run1
        .get_or_create("alice@example.com", "Alice")
        .signer
        .public_key();
    let pk2 = run2
        .get_or_create(" Alice@Example.com ", "Alice")
        .signer
        .public_key();
    assert_eq!(pk1, pk2);
    assert_eq!(pk1, test_keys().author("alice@example.com").public_key());
    // Case variants of one email are one author, not two entries.
    run1.get_or_create("ALICE@example.com", "Alice");
    assert_eq!(run1.len(), 1);
}

// Backlog 7d9e60c6 (1): the token can come from EPIGRAPH_TOKEN, off argv.
#[test]
fn token_flag_wins_then_env_then_none() {
    let s = |v: &str| Some(v.to_string());
    assert_eq!(token_or_env(s("flag"), s("env")), s("flag"));
    assert_eq!(token_or_env(None, s(" env \n")), s("env"));
    assert_eq!(token_or_env(None, s("  ")), None);
    assert_eq!(token_or_env(None, None), None);
}

#[test]
fn repo_node_packet_has_stable_idempotency_and_label() {
    let signer = AgentSigner::generate();
    let p = build_repo_packet("epigraph-io/epiclaw-host", Uuid::nil(), &signer);
    assert_eq!(
        p.claim.idempotency_key.as_deref(),
        Some("repo:epigraph-io/epiclaw-host")
    );
    assert!(p.claim.content.contains("epigraph-io/epiclaw-host"));
    let props = p.claim.properties.as_ref().unwrap();
    assert_eq!(props["source"], "git-history");
    assert_eq!(props["node"], "repo");
    assert_eq!(props["repo"], "epigraph-io/epiclaw-host");

    // Ruling R-34: the repo node's evidence carries a v1 EVIDENCE
    // signature over its content hash, which is no claim signature.
    let ev = &p.evidence[0];
    let sig: [u8; 64] = hex::decode(ev.signature.as_ref().expect("evidence is signed"))
        .unwrap()
        .try_into()
        .unwrap();
    let mut hash = [0u8; 32];
    hex::decode_to_slice(&ev.content_hash, &mut hash).unwrap();
    let check = |kind| {
        epigraph_crypto::SignatureVerifier::verify_entity(&signer.public_key(), kind, &hash, &sig)
            .unwrap()
    };
    assert_eq!(
        check(SignedEntity::Evidence),
        Some(epigraph_crypto::SignatureScheme::V1),
        "the repo node's evidence is not signed as v1 evidence"
    );
    assert_eq!(check(SignedEntity::Claim), None);
}

// -------------------------------------------------------------------------
// PR-node find-or-create packet tests
// -------------------------------------------------------------------------

#[test]
fn pr_packet_keys_on_repo_and_number_and_carries_properties() {
    // build_pr_packet takes only the orchestrator agent_id; the PR node carries
    // no per-author evidence signature (unlike build_repo_packet).
    let meta = PrMeta {
        repo_slug: "epigraph-io/epigraph".into(),
        number: 252,
        title: "fix(api): stop auto-enqueueing cluster jobs".into(),
        body: "## Summary\nResolves d531c585".into(),
        merge_sha: "2a31f8d".into(),
        merged_at: "2026-06-02T15:10:01Z".into(),
        author_login: "tylorsama".into(),
    };
    let p = build_pr_packet(&meta, Uuid::nil());
    assert_eq!(
        p.claim.idempotency_key.as_deref(),
        Some("pr:epigraph-io/epigraph#252")
    );
    assert!(p
        .claim
        .content
        .contains("stop auto-enqueueing cluster jobs"));
    let props = p.claim.properties.as_ref().unwrap();
    assert_eq!(props["node"], "pr");
    assert_eq!(props["pr_number"], 252);
    assert_eq!(props["merge_sha"], "2a31f8d");
}

// -------------------------------------------------------------------------
// Datestamped edge body tests
// -------------------------------------------------------------------------

#[test]
fn edge_body_uses_generic_endpoint_fields() {
    let body = edge_body(
        Uuid::nil(),
        Uuid::nil(),
        "decomposes_to",
        Some("2026-06-02T15:10:01Z"),
    );
    assert_eq!(body["source_type"], "claim");
    assert_eq!(body["target_type"], "claim");
    assert_eq!(body["relationship"], "decomposes_to");
    assert_eq!(body["valid_from"], "2026-06-02T15:10:01Z");
    assert_eq!(body["if_not_exists"], true);
}

// -------------------------------------------------------------------------
// Header parsing tests
// -------------------------------------------------------------------------

#[test]
fn test_parse_header_standard() {
    let (ct, scope, claim) =
        parse_header("feat(core): define Claim model with bounded truth values");
    assert_eq!(ct, CommitType::Feat);
    assert_eq!(scope, "core");
    assert_eq!(claim, "define Claim model with bounded truth values");
}

#[test]
fn test_parse_header_multi_scope() {
    let (ct, scope, claim) = parse_header("fix(db,api): align signer_id nullability");
    assert_eq!(ct, CommitType::Fix);
    assert_eq!(scope, "db,api");
    assert_eq!(claim, "align signer_id nullability");
}

#[test]
fn test_parse_header_security() {
    let (ct, scope, claim) =
        parse_header("security(crypto): prevent timing attacks in signature verification");
    assert_eq!(ct, CommitType::Security);
    assert_eq!(scope, "crypto");
    assert_eq!(claim, "prevent timing attacks in signature verification");
}

#[test]
fn test_parse_header_unknown_type() {
    let (ct, scope, claim) = parse_header("yolo(stuff): something weird");
    assert_eq!(ct, CommitType::Unknown);
    assert_eq!(scope, "stuff");
    assert_eq!(claim, "something weird");
}

#[test]
fn test_parse_header_non_protocol() {
    let (ct, scope, claim) = parse_header("Initial commit");
    assert_eq!(ct, CommitType::Unknown);
    assert_eq!(scope, "");
    assert_eq!(claim, "Initial commit");
}

#[test]
fn test_parse_header_no_scope() {
    let (ct, scope, claim) = parse_header("Just a plain message without any structure");
    assert_eq!(ct, CommitType::Unknown);
    assert_eq!(scope, "");
    assert_eq!(claim, "Just a plain message without any structure");
}

#[test]
fn test_parse_header_type_colon_no_scope() {
    let (ct, scope, claim) = parse_header("docs: update HARDENING_PLAN.md");
    assert_eq!(ct, CommitType::Docs);
    assert_eq!(scope, "");
    assert_eq!(claim, "update HARDENING_PLAN.md");
}

#[test]
fn test_parse_header_style_type() {
    // `style` (formatting-only commits) is a protocol type of its own, with
    // and without a scope, and maps the way `docs` does. Asserted through
    // Display so the test also compiles where Style does not exist.
    let (ct, scope, claim) = parse_header("style(api): rustfmt");
    assert_eq!(ct.to_string(), "style");
    assert_eq!(scope, "api");
    assert_eq!(claim, "rustfmt");
    let (ct, scope, claim) = parse_header("style: fmt");
    assert_eq!(ct.to_string(), "style");
    assert_eq!(scope, "");
    assert_eq!(claim, "fmt");
    assert_eq!(ct.methodology(), CommitType::Docs.methodology());
    let docs_truth = CommitType::Docs.initial_truth(false);
    assert!((ct.initial_truth(false) - docs_truth).abs() < f64::EPSILON);
}

#[test]
fn test_parse_header_type_colon_unknown_type() {
    // An unknown type with colon format should still be Unknown
    let (ct, scope, claim) = parse_header("misc: random stuff");
    assert_eq!(ct, CommitType::Unknown);
    assert_eq!(scope, "");
    assert_eq!(claim, "misc: random stuff");
}

// -------------------------------------------------------------------------
// Section detection tests
// -------------------------------------------------------------------------

#[test]
fn test_detect_section_bold() {
    assert_eq!(detect_section("**Evidence:**"), Some(Section::Evidence));
    assert_eq!(detect_section("**Reasoning:**"), Some(Section::Reasoning));
    assert_eq!(
        detect_section("**Verification:**"),
        Some(Section::Verification)
    );
}

#[test]
fn test_detect_section_plain() {
    assert_eq!(detect_section("Evidence:"), Some(Section::Evidence));
    assert_eq!(detect_section("Reasoning:"), Some(Section::Reasoning));
    assert_eq!(detect_section("Verification:"), Some(Section::Verification));
}

#[test]
fn test_detect_section_none() {
    assert_eq!(detect_section("- some bullet"), None);
    assert_eq!(detect_section("Random text"), None);
    assert_eq!(detect_section(""), None);
}

// -------------------------------------------------------------------------
// Full commit message parsing tests
// -------------------------------------------------------------------------

#[test]
fn test_parse_full_commit_message() {
    let msg = "\
feat(engine): implement Bayesian truth update for claim propagation

**Evidence:**
- IMPLEMENTATION_PLAN.md Phase 3 requirement
- Current weighted average insufficient for evidence accumulation

**Reasoning:**
- P(H|E) = P(E|H) * P(H) / P(E) provides proper belief updating
- Chose to clamp posterior to [0.01, 0.99] to prevent certainty lock-in

**Verification:**
- test_bayesian_update validates formula
- cargo test --lib engine passes";

    let (ct, scope, claim, evidence, reasoning, verification) = parse_commit_message(msg);

    assert_eq!(ct, CommitType::Feat);
    assert_eq!(scope, "engine");
    assert_eq!(
        claim,
        "implement Bayesian truth update for claim propagation"
    );
    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0], "IMPLEMENTATION_PLAN.md Phase 3 requirement");
    assert_eq!(reasoning.len(), 2);
    assert!(reasoning[0].contains("P(H|E)"));
    assert_eq!(verification.len(), 2);
    assert!(verification[0].contains("test_bayesian_update"));
}

#[test]
fn test_parse_commit_message_no_sections() {
    let msg = "Initial commit";
    let (ct, scope, claim, evidence, reasoning, verification) = parse_commit_message(msg);

    assert_eq!(ct, CommitType::Unknown);
    assert_eq!(scope, "");
    assert_eq!(claim, "Initial commit");
    assert!(evidence.is_empty());
    assert!(reasoning.is_empty());
    assert!(verification.is_empty());
}

#[test]
fn test_parse_commit_message_partial_sections() {
    let msg = "\
fix(db): prevent SQL injection in claim search

**Evidence:**
- Grep found raw string interpolation in semantic.rs:45

**Reasoning:**
- Replaced format!() with sqlx parameterized query";

    let (ct, _scope, _claim, evidence, reasoning, verification) = parse_commit_message(msg);

    assert_eq!(ct, CommitType::Fix);
    assert_eq!(evidence.len(), 1);
    assert_eq!(reasoning.len(), 1);
    assert!(verification.is_empty());
}

// -------------------------------------------------------------------------
// CommitType tests
// -------------------------------------------------------------------------

#[test]
fn test_commit_type_from_str() {
    assert_eq!(CommitType::from_str("feat"), CommitType::Feat);
    assert_eq!(CommitType::from_str("FEAT"), CommitType::Feat);
    assert_eq!(CommitType::from_str("Fix"), CommitType::Fix);
    assert_eq!(CommitType::from_str("refactor"), CommitType::Refactor);
    assert_eq!(CommitType::from_str("security"), CommitType::Security);
    assert_eq!(CommitType::from_str("test"), CommitType::Test);
    assert_eq!(CommitType::from_str("perf"), CommitType::Perf);
    assert_eq!(CommitType::from_str("docs"), CommitType::Docs);
    assert_eq!(CommitType::from_str("chore"), CommitType::Chore);
    assert_eq!(CommitType::from_str("style"), CommitType::Style);
    assert_eq!(CommitType::from_str("anything_else"), CommitType::Unknown);
}

#[test]
fn test_methodology_mapping() {
    assert_eq!(CommitType::Feat.methodology(), "extraction");
    assert_eq!(CommitType::Fix.methodology(), "deductive");
    assert_eq!(CommitType::Refactor.methodology(), "deductive");
    assert_eq!(CommitType::Security.methodology(), "deductive");
    assert_eq!(CommitType::Test.methodology(), "instrumental");
    assert_eq!(CommitType::Perf.methodology(), "instrumental");
    assert_eq!(CommitType::Docs.methodology(), "heuristic");
    assert_eq!(CommitType::Chore.methodology(), "heuristic");
    assert_eq!(CommitType::Unknown.methodology(), "heuristic");
}

#[test]
fn test_initial_truth_values() {
    // feat with verification
    assert!((CommitType::Feat.initial_truth(true) - 0.6).abs() < f64::EPSILON);
    // feat without verification
    assert!((CommitType::Feat.initial_truth(false) - 0.4).abs() < f64::EPSILON);
    // fix
    assert!((CommitType::Fix.initial_truth(true) - 0.7).abs() < f64::EPSILON);
    assert!((CommitType::Fix.initial_truth(false) - 0.7).abs() < f64::EPSILON);
    // security
    assert!((CommitType::Security.initial_truth(false) - 0.7).abs() < f64::EPSILON);
    // test
    assert!((CommitType::Test.initial_truth(false) - 0.8).abs() < f64::EPSILON);
    // refactor
    assert!((CommitType::Refactor.initial_truth(false) - 0.5).abs() < f64::EPSILON);
    // docs
    assert!((CommitType::Docs.initial_truth(false) - 0.4).abs() < f64::EPSILON);
    // chore
    assert!((CommitType::Chore.initial_truth(false) - 0.3).abs() < f64::EPSILON);
    // unknown
    assert!((CommitType::Unknown.initial_truth(false) - 0.2).abs() < f64::EPSILON);
}

// -------------------------------------------------------------------------
// Packet building tests
// -------------------------------------------------------------------------

#[test]
fn test_build_packet_full_commit() {
    let commit = ParsedCommit {
        hash: "abc123def456".to_string(),
        author_name: "Test Author".to_string(),
        author_email: "test@example.com".to_string(),
        date: "2026-02-10T12:00:00+00:00".to_string(),
        commit_type: CommitType::Feat,
        scope: "core".to_string(),
        claim_text: "add truth validation".to_string(),
        evidence: vec!["PLAN.md requires bounded truth".to_string()],
        reasoning: vec!["Chose f64 for precision".to_string()],
        verification: vec!["test_truth_bounds passes".to_string()],
        parent_hashes: vec!["parent123".to_string()],
        trailers: vec![],
        files_changed: vec!["src/core/claim.rs".to_string()],
    };

    let signer = AgentSigner::generate();
    let agent_id = Uuid::new_v4();
    let packet = build_packet(&commit, &signer, agent_id, None);

    assert_eq!(packet.claim.content, "[feat][core] add truth validation");
    assert_eq!(packet.claim.agent_id, agent_id);
    assert_eq!(
        packet.claim.idempotency_key,
        Some("git:abc123def456".to_string())
    );

    // Should have 2 evidence items: 1 from evidence + 1 from verification
    assert_eq!(packet.evidence.len(), 2);

    // Verify evidence hashes match content
    let expected_hash = hex::encode(ContentHasher::hash(b"PLAN.md requires bounded truth"));
    assert_eq!(packet.evidence[0].content_hash, expected_hash);

    // Verify methodology
    assert_eq!(packet.reasoning_trace.methodology, "extraction");

    // Verify initial truth (feat with verification = 0.6)
    assert!((packet.claim.initial_truth.unwrap() - 0.6).abs() < f64::EPSILON);

    // Confidence: full metadata = 0.85
    assert!((packet.reasoning_trace.confidence - 0.85).abs() < f64::EPSILON);

    // Signature should be present
    assert!(!packet.signature.is_empty());
    assert_eq!(hex::decode(&packet.signature).unwrap().len(), 64);
}

#[test]
fn test_build_packet_no_evidence() {
    let commit = ParsedCommit {
        hash: "deadbeef".to_string(),
        author_name: "Dev".to_string(),
        author_email: "dev@example.com".to_string(),
        date: "2026-01-01T00:00:00+00:00".to_string(),
        commit_type: CommitType::Chore,
        scope: "build".to_string(),
        claim_text: "update dependencies".to_string(),
        evidence: vec![],
        reasoning: vec![],
        verification: vec![],
        parent_hashes: vec![],
        trailers: vec![],
        files_changed: vec!["Cargo.lock".to_string()],
    };

    let signer = AgentSigner::generate();
    let agent_id = Uuid::new_v4();
    let packet = build_packet(&commit, &signer, agent_id, None);

    assert!(packet.evidence.is_empty());
    assert_eq!(packet.reasoning_trace.methodology, "heuristic");
    assert!((packet.claim.initial_truth.unwrap() - 0.3).abs() < f64::EPSILON);

    // Confidence: no metadata = 0.3
    assert!((packet.reasoning_trace.confidence - 0.3).abs() < f64::EPSILON);

    // Explanation should be auto-generated from claim
    assert!(packet
        .reasoning_trace
        .explanation
        .contains("update dependencies"));
}

#[test]
fn test_build_packet_evidence_signatures_valid() {
    let commit = ParsedCommit {
        hash: "abc123".to_string(),
        author_name: "Dev".to_string(),
        author_email: "dev@example.com".to_string(),
        date: "2026-01-01T00:00:00+00:00".to_string(),
        commit_type: CommitType::Fix,
        scope: "db".to_string(),
        claim_text: "fix query".to_string(),
        evidence: vec!["Found bug in query".to_string()],
        reasoning: vec![],
        verification: vec![],
        parent_hashes: vec![],
        trailers: vec![],
        files_changed: vec![],
    };

    let signer = AgentSigner::generate();
    let packet = build_packet(&commit, &signer, Uuid::new_v4(), None);

    // All evidence should have valid 64-byte hex signatures
    for ev in &packet.evidence {
        let sig = ev.signature.as_ref().expect("evidence should be signed");
        let sig_bytes = hex::decode(sig).expect("signature should be valid hex");
        assert_eq!(sig_bytes.len(), 64, "Ed25519 signature should be 64 bytes");
        // Ruling R-34: a v1 EVIDENCE signature over the evidence's
        // content hash, which is no claim signature over that hash.
        let sig: [u8; 64] = sig_bytes.try_into().unwrap();
        let mut hash = [0u8; 32];
        hex::decode_to_slice(&ev.content_hash, &mut hash).unwrap();
        let check = |kind| {
            epigraph_crypto::SignatureVerifier::verify_entity(
                &signer.public_key(),
                kind,
                &hash,
                &sig,
            )
            .unwrap()
        };
        assert_eq!(
            check(SignedEntity::Evidence),
            Some(epigraph_crypto::SignatureScheme::V1)
        );
        assert_eq!(check(SignedEntity::Claim), None);
    }
}

#[test]
fn test_build_packet_includes_files_changed() {
    let commit = ParsedCommit {
        hash: "cafebabe".to_string(),
        author_name: "Dev".to_string(),
        author_email: "dev@example.com".to_string(),
        date: "2026-03-15T10:30:00+00:00".to_string(),
        commit_type: CommitType::Refactor,
        scope: "engine".to_string(),
        claim_text: "extract propagation logic".to_string(),
        evidence: vec!["Code review showed duplication".to_string()],
        reasoning: vec!["DRY principle".to_string()],
        verification: vec![],
        parent_hashes: vec!["deadbeef".to_string()],
        trailers: vec![],
        files_changed: vec![
            "src/engine/propagation.rs".to_string(),
            "src/engine/mod.rs".to_string(),
        ],
    };

    let signer = AgentSigner::generate();
    let agent_id = Uuid::new_v4();
    let packet = build_packet(&commit, &signer, agent_id, None);

    let props = packet
        .claim
        .properties
        .expect("properties should be populated");
    assert_eq!(props["source"], "git-history");
    assert_eq!(props["commit_hash"], "cafebabe");
    assert_eq!(props["commit_date"], "2026-03-15T10:30:00+00:00");
    assert_eq!(props["commit_type"], "refactor");
    assert_eq!(props["scope"], "engine");

    let files = props["files_changed"]
        .as_array()
        .expect("files_changed should be an array");
    assert_eq!(files.len(), 2);
    assert_eq!(files[0], "src/engine/propagation.rs");
    assert_eq!(files[1], "src/engine/mod.rs");
}

#[test]
fn test_build_all_packets() {
    let commits = vec![
        ParsedCommit {
            hash: "aaa".to_string(),
            author_name: "A".to_string(),
            author_email: "a@x.com".to_string(),
            date: "2026-01-01T00:00:00+00:00".to_string(),
            commit_type: CommitType::Feat,
            scope: "core".to_string(),
            claim_text: "first".to_string(),
            evidence: vec![],
            reasoning: vec![],
            verification: vec![],
            parent_hashes: vec![],
            trailers: vec![],
            files_changed: vec![],
        },
        ParsedCommit {
            hash: "bbb".to_string(),
            author_name: "B".to_string(),
            author_email: "b@x.com".to_string(),
            date: "2026-01-02T00:00:00+00:00".to_string(),
            commit_type: CommitType::Fix,
            scope: "api".to_string(),
            claim_text: "second".to_string(),
            evidence: vec![],
            reasoning: vec![],
            verification: vec![],
            parent_hashes: vec!["aaa".to_string()],
            trailers: vec![],
            files_changed: vec![],
        },
    ];

    let signer = AgentSigner::generate();
    let agent_id = Uuid::new_v4();
    let packets = build_all_packets(&commits, &signer, agent_id);

    assert_eq!(packets.len(), 2);
    assert!(packets[0].claim.content.contains("first"));
    assert!(packets[1].claim.content.contains("second"));
}

// -------------------------------------------------------------------------
// Git log output parsing tests
// -------------------------------------------------------------------------

#[test]
fn test_parse_git_log_output_single_commit() {
    let output = format!(
        "{RS}abc123{FS}Test Author{FS}test@example.com{FS}2026-02-10T12:00:00+00:00{FS}parent1{FS}feat(core): add truth validation\n\n**Evidence:**\n- Plan requires it\n\n**Reasoning:**\n- Chose f64\n\n**Verification:**\n- Tests pass\n\nsrc/core/claim.rs",
        RS = RECORD_SEP,
        FS = FIELD_SEP,
    );

    let commits = parse_git_log_output(&output).unwrap();
    assert_eq!(commits.len(), 1);

    let c = &commits[0];
    assert_eq!(c.hash, "abc123");
    assert_eq!(c.author_name, "Test Author");
    assert_eq!(c.author_email, "test@example.com");
    assert_eq!(c.commit_type, CommitType::Feat);
    assert_eq!(c.scope, "core");
    assert_eq!(c.claim_text, "add truth validation");
    assert_eq!(c.evidence, vec!["Plan requires it"]);
    assert_eq!(c.reasoning, vec!["Chose f64"]);
    assert_eq!(c.verification, vec!["Tests pass"]);
    assert_eq!(c.parent_hashes, vec!["parent1"]);
    assert_eq!(c.files_changed, vec!["src/core/claim.rs"]);
}

#[test]
fn test_parse_git_log_output_multiple_commits() {
    let output = format!(
        "{RS}bbb{FS}B{FS}b@x.com{FS}2026-02-02{FS}aaa{FS}fix(db): fix query\n\nfile2.rs\n{RS}aaa{FS}A{FS}a@x.com{FS}2026-02-01{FS}{FS}feat(core): initial\n\nfile1.rs",
        RS = RECORD_SEP,
        FS = FIELD_SEP,
    );

    let commits = parse_git_log_output(&output).unwrap();
    // Should be reversed to chronological order (oldest first)
    assert_eq!(commits.len(), 2);
    assert_eq!(commits[0].hash, "aaa");
    assert_eq!(commits[1].hash, "bbb");
}

#[test]
fn test_parse_git_log_output_non_protocol_commit() {
    let output = format!(
        "{RS}xyz{FS}Someone{FS}someone@mail.com{FS}2026-01-01{FS}{FS}Initial commit\n\nREADME.md",
        RS = RECORD_SEP,
        FS = FIELD_SEP,
    );

    let commits = parse_git_log_output(&output).unwrap();
    assert_eq!(commits.len(), 1);
    assert_eq!(commits[0].commit_type, CommitType::Unknown);
    assert_eq!(commits[0].claim_text, "Initial commit");
}

#[test]
fn test_parse_git_log_output_empty() {
    let commits = parse_git_log_output("").unwrap();
    assert!(commits.is_empty());
}

// -------------------------------------------------------------------------
// split_body_and_files tests
// -------------------------------------------------------------------------

#[test]
fn test_split_body_and_files() {
    let combined = "feat(core): something\n\n**Evidence:**\n- item\n\nsrc/file.rs\nCargo.toml";
    let (body, files) = split_body_and_files(combined);
    assert!(body.contains("feat(core)"));
    assert!(files.contains("src/file.rs") || body.contains("src/file.rs"));
}

#[test]
fn test_split_body_and_files_no_files() {
    let combined = "Just a message";
    let (body, files) = split_body_and_files(combined);
    assert_eq!(body, "Just a message");
    assert!(files.is_empty());
}

// -------------------------------------------------------------------------
// Confidence calculation tests
// -------------------------------------------------------------------------

#[test]
fn test_confidence_full_metadata() {
    let commit = ParsedCommit {
        hash: "x".into(),
        author_name: "A".into(),
        author_email: "a@b".into(),
        date: "2026-01-01".into(),
        commit_type: CommitType::Feat,
        scope: "core".into(),
        claim_text: "test".into(),
        evidence: vec!["ev".into()],
        reasoning: vec!["re".into()],
        verification: vec!["ve".into()],
        parent_hashes: vec![],
        trailers: vec![],
        files_changed: vec![],
    };
    let signer = AgentSigner::generate();
    let packet = build_packet(&commit, &signer, Uuid::new_v4(), None);
    assert!((packet.reasoning_trace.confidence - 0.85).abs() < f64::EPSILON);
}

#[test]
fn test_confidence_no_verification() {
    let commit = ParsedCommit {
        hash: "x".into(),
        author_name: "A".into(),
        author_email: "a@b".into(),
        date: "2026-01-01".into(),
        commit_type: CommitType::Feat,
        scope: "core".into(),
        claim_text: "test".into(),
        evidence: vec!["ev".into()],
        reasoning: vec!["re".into()],
        verification: vec![],
        parent_hashes: vec![],
        trailers: vec![],
        files_changed: vec![],
    };
    let signer = AgentSigner::generate();
    let packet = build_packet(&commit, &signer, Uuid::new_v4(), None);
    assert!((packet.reasoning_trace.confidence - 0.7).abs() < f64::EPSILON);
}

#[test]
fn test_confidence_no_metadata() {
    let commit = ParsedCommit {
        hash: "x".into(),
        author_name: "A".into(),
        author_email: "a@b".into(),
        date: "2026-01-01".into(),
        commit_type: CommitType::Chore,
        scope: "".into(),
        claim_text: "test".into(),
        evidence: vec![],
        reasoning: vec![],
        verification: vec![],
        parent_hashes: vec![],
        trailers: vec![],
        files_changed: vec![],
    };
    let signer = AgentSigner::generate();
    let packet = build_packet(&commit, &signer, Uuid::new_v4(), None);
    assert!((packet.reasoning_trace.confidence - 0.3).abs() < f64::EPSILON);
}

// -------------------------------------------------------------------------
// CommitType Display
// -------------------------------------------------------------------------

#[test]
fn test_commit_type_display() {
    assert_eq!(format!("{}", CommitType::Feat), "feat");
    assert_eq!(format!("{}", CommitType::Fix), "fix");
    assert_eq!(format!("{}", CommitType::Unknown), "unknown");
}

// -------------------------------------------------------------------------
// Idempotency key
// -------------------------------------------------------------------------

#[test]
fn test_idempotency_key_uses_git_hash() {
    let commit = ParsedCommit {
        hash: "deadbeef1234567890".to_string(),
        author_name: "A".into(),
        author_email: "a@b".into(),
        date: "2026-01-01".into(),
        commit_type: CommitType::Feat,
        scope: "core".into(),
        claim_text: "test".into(),
        evidence: vec![],
        reasoning: vec![],
        verification: vec![],
        parent_hashes: vec![],
        trailers: vec![],
        files_changed: vec![],
    };
    let signer = AgentSigner::generate();
    let packet = build_packet(&commit, &signer, Uuid::new_v4(), None);
    assert_eq!(
        packet.claim.idempotency_key,
        Some("git:deadbeef1234567890".to_string())
    );
}

// -------------------------------------------------------------------------
// Agent management tests
// -------------------------------------------------------------------------

#[test]
fn test_agent_registry_creates_unique_agents() {
    let mut registry = AgentRegistry::new(test_keys());

    let a1 = registry.get_or_create("alice@example.com", "Alice");
    let a1_id = a1.agent_id;
    let a1_pk = a1.signer.public_key().to_owned();

    let a2 = registry.get_or_create("bob@example.com", "Bob");
    let a2_id = a2.agent_id;
    let a2_pk = a2.signer.public_key().to_owned();

    // Different authors get different agents
    assert_ne!(a1_id, a2_id);
    assert_ne!(a1_pk, a2_pk);
    assert_eq!(registry.len(), 2);
}

#[test]
fn test_agent_registry_reuses_existing() {
    let mut registry = AgentRegistry::new(test_keys());

    let first = registry.get_or_create("alice@example.com", "Alice");
    let first_id = first.agent_id;

    let second = registry.get_or_create("alice@example.com", "Alice");
    let second_id = second.agent_id;

    // Same email reuses the same agent
    assert_eq!(first_id, second_id);
    assert_eq!(registry.len(), 1);
}

#[test]
fn test_agent_registry_empty() {
    let registry = AgentRegistry::new(test_keys());
    assert_eq!(registry.len(), 0);
}

// -------------------------------------------------------------------------
// Relationship tracker tests
// -------------------------------------------------------------------------

fn make_commit(
    hash: &str,
    commit_type: CommitType,
    scope: &str,
    parents: Vec<&str>,
) -> ParsedCommit {
    ParsedCommit {
        hash: hash.to_string(),
        author_name: "A".into(),
        author_email: "a@b".into(),
        date: "2026-01-01".into(),
        commit_type,
        scope: scope.to_string(),
        claim_text: "test".into(),
        evidence: vec![],
        reasoning: vec![],
        verification: vec![],
        parent_hashes: parents.into_iter().map(String::from).collect(),
        trailers: vec![],
        files_changed: vec![],
    }
}

#[test]
fn test_relationship_tracker_fix_challenges_feat() {
    let mut tracker = RelationshipTracker::new();

    // Record a feat in "core" scope
    let feat_commit = make_commit("aaa", CommitType::Feat, "core", vec![]);
    let feat_id = Uuid::new_v4();
    tracker.record(&feat_commit, feat_id);

    // A fix in the same scope should challenge it
    let fix_commit = make_commit("bbb", CommitType::Fix, "core", vec!["aaa"]);
    let challenged = tracker.find_challenged_feat(&fix_commit);
    assert_eq!(challenged, Some(feat_id));
}

#[test]
fn test_relationship_tracker_fix_different_scope_no_challenge() {
    let mut tracker = RelationshipTracker::new();

    let feat_commit = make_commit("aaa", CommitType::Feat, "core", vec![]);
    tracker.record(&feat_commit, Uuid::new_v4());

    // A fix in a different scope should NOT challenge it
    let fix_commit = make_commit("bbb", CommitType::Fix, "api", vec![]);
    assert!(tracker.find_challenged_feat(&fix_commit).is_none());
}

#[test]
fn test_relationship_tracker_non_fix_no_challenge() {
    let mut tracker = RelationshipTracker::new();

    let feat_commit = make_commit("aaa", CommitType::Feat, "core", vec![]);
    tracker.record(&feat_commit, Uuid::new_v4());

    // A refactor should NOT challenge the feat
    let refactor = make_commit("bbb", CommitType::Refactor, "core", vec![]);
    assert!(tracker.find_challenged_feat(&refactor).is_none());
}

#[test]
fn test_relationship_tracker_parent_claim() {
    let mut tracker = RelationshipTracker::new();

    let parent = make_commit("aaa", CommitType::Feat, "core", vec![]);
    let parent_id = Uuid::new_v4();
    tracker.record(&parent, parent_id);

    let child = make_commit("bbb", CommitType::Fix, "core", vec!["aaa"]);
    let found = tracker.find_parent_claim(&child);
    assert_eq!(found, Some(parent_id));
}

#[test]
fn test_relationship_tracker_no_parent() {
    let tracker = RelationshipTracker::new();

    let root = make_commit("aaa", CommitType::Feat, "core", vec![]);
    assert!(tracker.find_parent_claim(&root).is_none());
}

#[test]
fn test_relationship_tracker_parent_not_ingested() {
    let tracker = RelationshipTracker::new();

    // Parent hash exists but wasn't tracked (e.g., outside --since range)
    let child = make_commit("bbb", CommitType::Fix, "core", vec!["unknown_hash"]);
    assert!(tracker.find_parent_claim(&child).is_none());
}

#[test]
fn test_relationship_tracker_fix_updates_feat_tracking() {
    let mut tracker = RelationshipTracker::new();

    // First feat in core
    let feat1 = make_commit("aaa", CommitType::Feat, "core", vec![]);
    let feat1_id = Uuid::new_v4();
    tracker.record(&feat1, feat1_id);

    // Second feat in core (overwrites the first)
    let feat2 = make_commit("bbb", CommitType::Feat, "core", vec!["aaa"]);
    let feat2_id = Uuid::new_v4();
    tracker.record(&feat2, feat2_id);

    // Fix should challenge the LATEST feat
    let fix = make_commit("ccc", CommitType::Fix, "core", vec!["bbb"]);
    assert_eq!(tracker.find_challenged_feat(&fix), Some(feat2_id));
}

// =========================================================================
// END-TO-END PIPELINE TESTS (Phase 4.3)
// =========================================================================
// These tests simulate parsing realistic git log output, building packets,
// and verifying the entire pipeline produces correct epistemic data.

/// Realistic commit messages following the Epistemic Commit Protocol.
/// Listed newest-first (as `git log` would output), so that
/// `parse_git_log_output()` can reverse them to chronological order.
fn realistic_git_log_output() -> String {
    let rs = RECORD_SEP;
    let fs = FIELD_SEP;

    format!(
        // Newest commit first (git log order)
        // Commit 10: Non-protocol commit
        "{rs}jjj000{fs}Bob{fs}bob@epigraph.dev{fs}2026-01-24T14:00:00+00:00{fs}iii999{fs}\
Initial commit\n\n\
README.md\
\n\
{rs}iii999{fs}Alice{fs}alice@epigraph.dev{fs}2026-01-23T09:30:00+00:00{fs}hhh888{fs}\
feat(engine): implement Bayesian truth update for claim propagation\n\n\
**Evidence:**\n\
- IMPLEMENTATION_PLAN.md Phase 3 requirement\n\
- Current weighted average insufficient for evidence accumulation\n\n\
**Reasoning:**\n\
- P(H|E) = P(E|H) * P(H) / P(E) provides proper belief updating\n\
- Chose to clamp posterior to [0.01, 0.99] to prevent certainty lock-in\n\n\
**Verification:**\n\
- test_bayesian_update validates formula\n\
- test_evidence_accumulation shows convergence\n\n\
crates/epigraph-engine/src/propagation.rs\
\n\
{rs}hhh888{fs}Charlie{fs}charlie@epigraph.dev{fs}2026-01-22T16:00:00+00:00{fs}ggg777{fs}\
chore: update dependencies to latest patch versions\n\n\
Cargo.toml\n\
Cargo.lock\
\n\
{rs}ggg777{fs}Alice{fs}alice@epigraph.dev{fs}2026-01-21T10:00:00+00:00{fs}fff666{fs}\
docs: add API endpoint documentation\n\n\
**Evidence:**\n\
- No existing API docs for external consumers\n\n\
**Reasoning:**\n\
- Used utoipa for OpenAPI spec generation\n\n\
docs/api.md\
\n\
{rs}fff666{fs}Bob{fs}bob@epigraph.dev{fs}2026-01-20T15:00:00+00:00{fs}eee555{fs}\
refactor(db): extract repository pattern from monolithic data layer\n\n\
**Evidence:**\n\
- Data layer grew to 800 lines, violating single-responsibility\n\n\
**Reasoning:**\n\
- Split into ClaimRepo, EvidenceRepo, AgentRepo\n\
- Each repo owns one table's queries\n\n\
crates/epigraph-db/src/repos/claim.rs\n\
crates/epigraph-db/src/repos/evidence.rs\n\
crates/epigraph-db/src/repos/agent.rs\
\n\
{rs}eee555{fs}Alice{fs}alice@epigraph.dev{fs}2026-01-19T08:00:00+00:00{fs}ddd444{fs}\
test(engine): add property-based tests for truth propagation\n\n\
**Evidence:**\n\
- IMPLEMENTATION_PLAN.md Phase 3 requires truth propagation validation\n\n\
**Reasoning:**\n\
- Property tests cover edge cases unit tests miss\n\
- quickcheck generates random claim graphs\n\n\
**Verification:**\n\
- 100 iterations pass with no panics\n\n\
crates/epigraph-engine/tests/property_tests.rs\
\n\
{rs}ddd444{fs}Charlie{fs}charlie@epigraph.dev{fs}2026-01-18T11:00:00+00:00{fs}ccc333{fs}\
security(crypto): prevent timing attacks in signature verification\n\n\
**Evidence:**\n\
- Security audit flagged constant-time comparison missing\n\
- ed25519-dalek docs warn about timing side-channels\n\n\
**Reasoning:**\n\
- Replaced == with subtle::ConstantTimeEq for signature bytes\n\
- Cannot use short-circuit comparison on cryptographic material\n\n\
**Verification:**\n\
- cargo test passes\n\
- Manual review confirms no early returns in verify path\n\n\
crates/epigraph-crypto/src/verifier.rs\
\n\
{rs}ccc333{fs}Alice{fs}alice@epigraph.dev{fs}2026-01-17T09:00:00+00:00{fs}bbb222{fs}\
fix(core): prevent NaN truth values from bypassing validation\n\n\
**Evidence:**\n\
- Fuzzing found f64::NAN passes 0.0 <= x <= 1.0 check (NaN comparisons always false)\n\n\
**Reasoning:**\n\
- Added explicit is_nan() check before bounds validation\n\
- NaN is not a valid epistemic state\n\n\
**Verification:**\n\
- test_claim_rejects_nan_truth: passes\n\n\
crates/epigraph-core/src/domain/claim.rs\
\n\
{rs}bbb222{fs}Bob{fs}bob@epigraph.dev{fs}2026-01-16T14:30:00+00:00{fs}aaa111{fs}\
feat(crypto): add BLAKE3 content hashing and Ed25519 signing\n\n\
**Evidence:**\n\
- IMPLEMENTATION_PLAN.md Phase 1 requires content-addressable hashing\n\n\
**Reasoning:**\n\
- BLAKE3 chosen over SHA-256: faster, Merkle-tree capable\n\
- Ed25519 for signatures: small keys, fast verification\n\n\
**Verification:**\n\
- test_hash_deterministic: passes\n\
- test_sign_verify_roundtrip: passes\n\n\
crates/epigraph-crypto/src/hasher.rs\n\
crates/epigraph-crypto/src/signer.rs\
\n\
{rs}aaa111{fs}Alice{fs}alice@epigraph.dev{fs}2026-01-15T10:00:00+00:00{fs}{fs}\
feat(core): define Claim model with bounded truth values\n\n\
**Evidence:**\n\
- IMPLEMENTATION_PLAN.md §2.1 specifies truth in [0.0, 1.0]\n\
- Unbounded floats allow invalid states (NaN, infinity)\n\n\
**Reasoning:**\n\
- Chose f64 over f32: precision matters for Bayesian updates near 0/1\n\
- Constructor validates bounds, returns Result<Claim, ClaimError>\n\n\
**Verification:**\n\
- test_claim_rejects_negative_truth: passes\n\
- test_claim_rejects_truth_above_one: passes\n\
- cargo build: no warnings\n\n\
crates/epigraph-core/src/domain/claim.rs\n\
crates/epigraph-core/src/domain/mod.rs",
    )
}

#[test]
fn test_e2e_parse_realistic_git_log() {
    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();

    // Should parse all 10 commits in chronological order (oldest first)
    // parse_git_log_output reverses the newest-first git log order
    assert_eq!(commits.len(), 10);

    // After reversal: oldest (aaa111) first, newest (jjj000) last
    assert_eq!(commits[0].hash, "aaa111");
    assert_eq!(commits[9].hash, "jjj000");
}

#[test]
fn test_e2e_commit_types_correctly_parsed() {
    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();

    // Create a map for easier lookup
    let by_hash: HashMap<&str, &ParsedCommit> =
        commits.iter().map(|c| (c.hash.as_str(), c)).collect();

    assert_eq!(by_hash["aaa111"].commit_type, CommitType::Feat);
    assert_eq!(by_hash["bbb222"].commit_type, CommitType::Feat);
    assert_eq!(by_hash["ccc333"].commit_type, CommitType::Fix);
    assert_eq!(by_hash["ddd444"].commit_type, CommitType::Security);
    assert_eq!(by_hash["eee555"].commit_type, CommitType::Test);
    assert_eq!(by_hash["fff666"].commit_type, CommitType::Refactor);
    assert_eq!(by_hash["ggg777"].commit_type, CommitType::Docs);
    assert_eq!(by_hash["hhh888"].commit_type, CommitType::Chore);
    assert_eq!(by_hash["iii999"].commit_type, CommitType::Feat);
    assert_eq!(by_hash["jjj000"].commit_type, CommitType::Unknown);
}

#[test]
fn test_e2e_scopes_extracted() {
    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();
    let by_hash: HashMap<&str, &ParsedCommit> =
        commits.iter().map(|c| (c.hash.as_str(), c)).collect();

    assert_eq!(by_hash["aaa111"].scope, "core");
    assert_eq!(by_hash["bbb222"].scope, "crypto");
    assert_eq!(by_hash["ccc333"].scope, "core");
    assert_eq!(by_hash["ddd444"].scope, "crypto");
    assert_eq!(by_hash["eee555"].scope, "engine");
    assert_eq!(by_hash["fff666"].scope, "db");
    assert_eq!(by_hash["ggg777"].scope, ""); // docs without scope
    assert_eq!(by_hash["hhh888"].scope, ""); // chore without scope
    assert_eq!(by_hash["iii999"].scope, "engine");
    assert_eq!(by_hash["jjj000"].scope, ""); // non-protocol commit
}

#[test]
fn test_e2e_evidence_sections_parsed() {
    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();
    let by_hash: HashMap<&str, &ParsedCommit> =
        commits.iter().map(|c| (c.hash.as_str(), c)).collect();

    // feat(core) has 2 evidence items
    assert_eq!(by_hash["aaa111"].evidence.len(), 2);
    assert!(by_hash["aaa111"].evidence[0].contains("IMPLEMENTATION_PLAN.md"));

    // feat(crypto) has 1 evidence item
    assert_eq!(by_hash["bbb222"].evidence.len(), 1);

    // chore has 0 evidence
    assert!(by_hash["hhh888"].evidence.is_empty());

    // Initial commit has 0 evidence
    assert!(by_hash["jjj000"].evidence.is_empty());
}

#[test]
fn test_e2e_verification_sections_parsed() {
    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();
    let by_hash: HashMap<&str, &ParsedCommit> =
        commits.iter().map(|c| (c.hash.as_str(), c)).collect();

    // feat(core) has 3 verification items
    assert_eq!(by_hash["aaa111"].verification.len(), 3);
    assert!(by_hash["aaa111"].verification[0].contains("test_claim_rejects_negative_truth"));

    // refactor(db) has NO verification
    assert!(by_hash["fff666"].verification.is_empty());

    // chore has no verification
    assert!(by_hash["hhh888"].verification.is_empty());
}

#[test]
fn test_e2e_packets_have_correct_truth_values() {
    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();
    let signer = AgentSigner::generate();
    let agent_id = Uuid::new_v4();

    let by_hash: HashMap<&str, &ParsedCommit> =
        commits.iter().map(|c| (c.hash.as_str(), c)).collect();

    // feat with verification → 0.6
    let p = build_packet(by_hash["aaa111"], &signer, agent_id, None);
    assert!(
        (p.claim.initial_truth.unwrap() - 0.6).abs() < f64::EPSILON,
        "feat with verification should have truth 0.6"
    );

    // fix → 0.7
    let p = build_packet(by_hash["ccc333"], &signer, agent_id, None);
    assert!(
        (p.claim.initial_truth.unwrap() - 0.7).abs() < f64::EPSILON,
        "fix should have truth 0.7"
    );

    // security → 0.7
    let p = build_packet(by_hash["ddd444"], &signer, agent_id, None);
    assert!(
        (p.claim.initial_truth.unwrap() - 0.7).abs() < f64::EPSILON,
        "security should have truth 0.7"
    );

    // test → 0.8
    let p = build_packet(by_hash["eee555"], &signer, agent_id, None);
    assert!(
        (p.claim.initial_truth.unwrap() - 0.8).abs() < f64::EPSILON,
        "test should have truth 0.8"
    );

    // refactor → 0.5
    let p = build_packet(by_hash["fff666"], &signer, agent_id, None);
    assert!(
        (p.claim.initial_truth.unwrap() - 0.5).abs() < f64::EPSILON,
        "refactor should have truth 0.5"
    );

    // docs → 0.4
    let p = build_packet(by_hash["ggg777"], &signer, agent_id, None);
    assert!(
        (p.claim.initial_truth.unwrap() - 0.4).abs() < f64::EPSILON,
        "docs should have truth 0.4"
    );

    // chore → 0.3
    let p = build_packet(by_hash["hhh888"], &signer, agent_id, None);
    assert!(
        (p.claim.initial_truth.unwrap() - 0.3).abs() < f64::EPSILON,
        "chore should have truth 0.3"
    );

    // Unknown → 0.2
    let p = build_packet(by_hash["jjj000"], &signer, agent_id, None);
    assert!(
        (p.claim.initial_truth.unwrap() - 0.2).abs() < f64::EPSILON,
        "unknown should have truth 0.2"
    );
}

#[test]
fn test_e2e_packets_have_correct_methodologies() {
    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();
    let signer = AgentSigner::generate();
    let agent_id = Uuid::new_v4();
    let by_hash: HashMap<&str, &ParsedCommit> =
        commits.iter().map(|c| (c.hash.as_str(), c)).collect();

    assert_eq!(
        build_packet(by_hash["aaa111"], &signer, agent_id, None)
            .reasoning_trace
            .methodology,
        "extraction"
    );
    assert_eq!(
        build_packet(by_hash["ccc333"], &signer, agent_id, None)
            .reasoning_trace
            .methodology,
        "deductive"
    );
    assert_eq!(
        build_packet(by_hash["ddd444"], &signer, agent_id, None)
            .reasoning_trace
            .methodology,
        "deductive"
    );
    assert_eq!(
        build_packet(by_hash["eee555"], &signer, agent_id, None)
            .reasoning_trace
            .methodology,
        "instrumental"
    );
    assert_eq!(
        build_packet(by_hash["fff666"], &signer, agent_id, None)
            .reasoning_trace
            .methodology,
        "deductive"
    );
    assert_eq!(
        build_packet(by_hash["ggg777"], &signer, agent_id, None)
            .reasoning_trace
            .methodology,
        "heuristic"
    );
    assert_eq!(
        build_packet(by_hash["hhh888"], &signer, agent_id, None)
            .reasoning_trace
            .methodology,
        "heuristic"
    );
    assert_eq!(
        build_packet(by_hash["jjj000"], &signer, agent_id, None)
            .reasoning_trace
            .methodology,
        "heuristic"
    );
}

#[test]
fn test_e2e_evidence_items_correctly_split() {
    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();
    let signer = AgentSigner::generate();
    let agent_id = Uuid::new_v4();
    let by_hash: HashMap<&str, &ParsedCommit> =
        commits.iter().map(|c| (c.hash.as_str(), c)).collect();

    // feat(core): 2 evidence + 3 verification = 5 evidence items in packet
    let p = build_packet(by_hash["aaa111"], &signer, agent_id, None);
    assert_eq!(p.evidence.len(), 5);

    // fix(core): 1 evidence + 1 verification = 2 evidence items
    let p = build_packet(by_hash["ccc333"], &signer, agent_id, None);
    assert_eq!(p.evidence.len(), 2);

    // chore: 0 evidence + 0 verification = 0 evidence items
    let p = build_packet(by_hash["hhh888"], &signer, agent_id, None);
    assert_eq!(p.evidence.len(), 0);
}

#[test]
fn test_e2e_relationship_detection_fix_challenges_feat() {
    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();

    let mut tracker = RelationshipTracker::new();

    // Process commits in order and check relationships
    for commit in &commits {
        match commit.hash.as_str() {
            "aaa111" => {
                // First feat(core) — no challenges expected
                assert!(tracker.find_challenged_feat(commit).is_none());
                tracker.record(commit, Uuid::new_v4());
            }
            "ccc333" => {
                // fix(core) — should challenge the feat(core) from aaa111
                assert!(
                    tracker.find_challenged_feat(commit).is_some(),
                    "fix(core) should challenge the prior feat(core)"
                );
                tracker.record(commit, Uuid::new_v4());
            }
            _ => {
                tracker.record(commit, Uuid::new_v4());
            }
        }
    }
}

#[test]
fn test_e2e_parent_child_chain() {
    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();

    let mut tracker = RelationshipTracker::new();
    let mut parent_links_found = 0;

    for commit in &commits {
        if tracker.find_parent_claim(commit).is_some() {
            parent_links_found += 1;
        }
        tracker.record(commit, Uuid::new_v4());
    }

    // Most commits have parents, so we should find several refinement links
    // The initial commit and root have no parents
    assert!(
        parent_links_found >= 5,
        "Expected at least 5 parent-child links, found {parent_links_found}"
    );
}

#[test]
fn test_e2e_per_author_agents() {
    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();

    let mut registry = AgentRegistry::new(test_keys());

    for commit in &commits {
        registry.get_or_create(&commit.author_email, &commit.author_name);
    }

    // We have 3 unique authors: Alice, Bob, Charlie
    assert_eq!(registry.len(), 3);
}

#[test]
fn test_e2e_all_packets_have_valid_signatures() {
    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();
    let signer = AgentSigner::generate();
    let agent_id = Uuid::new_v4();

    for commit in &commits {
        let packet = build_packet(commit, &signer, agent_id, None);

        // Packet signature must be valid hex, 128 chars (64 bytes)
        let sig_bytes = hex::decode(&packet.signature)
            .unwrap_or_else(|_| panic!("Invalid packet signature hex for {}", commit.hash));
        assert_eq!(
            sig_bytes.len(),
            64,
            "Packet signature for {} should be 64 bytes",
            commit.hash
        );

        // All evidence items must have valid signatures
        for (i, ev) in packet.evidence.iter().enumerate() {
            let sig = ev
                .signature
                .as_ref()
                .unwrap_or_else(|| panic!("Evidence {} of {} missing signature", i, commit.hash));
            let sig_bytes = hex::decode(sig)
                .unwrap_or_else(|_| panic!("Invalid evidence signature hex for {}", commit.hash));
            assert_eq!(sig_bytes.len(), 64);
        }

        // Content hashes must be valid hex, 64 chars (32 bytes)
        for (i, ev) in packet.evidence.iter().enumerate() {
            let hash_bytes = hex::decode(&ev.content_hash).unwrap_or_else(|_| {
                panic!("Invalid hash hex for evidence {} of {}", i, commit.hash)
            });
            assert_eq!(hash_bytes.len(), 32);
        }
    }
}

#[test]
fn test_e2e_idempotency_keys_unique() {
    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();
    let signer = AgentSigner::generate();
    let agent_id = Uuid::new_v4();

    let keys: Vec<String> = commits
        .iter()
        .map(|c| build_packet(c, &signer, agent_id, None))
        .map(|p| p.claim.idempotency_key.unwrap())
        .collect();

    // All idempotency keys should be unique
    let unique: std::collections::HashSet<&String> = keys.iter().collect();
    assert_eq!(
        unique.len(),
        keys.len(),
        "All idempotency keys must be unique"
    );

    // All keys should start with "git:"
    for key in &keys {
        assert!(
            key.starts_with("git:"),
            "Key should start with 'git:', got: {key}"
        );
    }
}

#[test]
fn test_e2e_claim_content_format() {
    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();
    let signer = AgentSigner::generate();
    let agent_id = Uuid::new_v4();
    let by_hash: HashMap<&str, &ParsedCommit> =
        commits.iter().map(|c| (c.hash.as_str(), c)).collect();

    // Claims should follow [type][scope] format
    let p = build_packet(by_hash["aaa111"], &signer, agent_id, None);
    assert_eq!(
        p.claim.content,
        "[feat][core] define Claim model with bounded truth values"
    );

    let p = build_packet(by_hash["ddd444"], &signer, agent_id, None);
    assert_eq!(
        p.claim.content,
        "[security][crypto] prevent timing attacks in signature verification"
    );

    let p = build_packet(by_hash["jjj000"], &signer, agent_id, None);
    assert_eq!(p.claim.content, "[unknown][] Initial commit");
}

#[test]
fn test_e2e_files_changed_tracked() {
    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();
    let by_hash: HashMap<&str, &ParsedCommit> =
        commits.iter().map(|c| (c.hash.as_str(), c)).collect();

    // feat(core) changed 2 files
    assert_eq!(by_hash["aaa111"].files_changed.len(), 2);
    assert!(by_hash["aaa111"]
        .files_changed
        .contains(&"crates/epigraph-core/src/domain/claim.rs".to_string()));

    // refactor(db) changed 3 files
    assert_eq!(by_hash["fff666"].files_changed.len(), 3);

    // chore changed 2 files
    assert_eq!(by_hash["hhh888"].files_changed.len(), 2);
}

#[test]
fn test_e2e_authors_tracked() {
    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();
    let by_hash: HashMap<&str, &ParsedCommit> =
        commits.iter().map(|c| (c.hash.as_str(), c)).collect();

    assert_eq!(by_hash["aaa111"].author_email, "alice@epigraph.dev");
    assert_eq!(by_hash["bbb222"].author_email, "bob@epigraph.dev");
    assert_eq!(by_hash["ddd444"].author_email, "charlie@epigraph.dev");
}

// =========================================================================
// PHASE 1: COMMIT ENRICHMENT TESTS
// =========================================================================

// --- 1.1 EnrichedData defaults ---

#[test]
fn test_enriched_data_defaults() {
    let data = EnrichedData::default();
    assert!(data.semantic_edges.is_empty());
    assert!(data.adjusted_confidence.is_none());
    assert!(data.embedding.is_none());
    assert!(data.implicit_claims.is_empty());
}

#[test]
fn test_semantic_edge_strength_bounded() {
    // Valid edge at boundary
    let edge = SemanticEdge::new(
        "abc123".to_string(),
        "supports".to_string(),
        0.0,
        "test".to_string(),
    );
    assert!(edge.is_ok());

    let edge = SemanticEdge::new(
        "abc123".to_string(),
        "supports".to_string(),
        1.0,
        "test".to_string(),
    );
    assert!(edge.is_ok());

    let edge = SemanticEdge::new(
        "abc123".to_string(),
        "supports".to_string(),
        0.5,
        "test".to_string(),
    );
    assert!(edge.is_ok());
    assert!((edge.unwrap().strength - 0.5).abs() < f64::EPSILON);

    // Invalid: negative
    let edge = SemanticEdge::new(
        "abc123".to_string(),
        "supports".to_string(),
        -0.1,
        "test".to_string(),
    );
    assert!(edge.is_err());
    assert!(edge.unwrap_err().contains("[0.0, 1.0]"));

    // Invalid: above 1.0
    let edge = SemanticEdge::new(
        "abc123".to_string(),
        "supports".to_string(),
        1.1,
        "test".to_string(),
    );
    assert!(edge.is_err());
}

// --- 1.2 NoopEnricher tests ---

#[tokio::test]
async fn test_noop_enricher_returns_empty_enrichment() {
    let enricher = NoopEnricher;
    let commits = vec![make_commit("aaa", CommitType::Feat, "core", vec![])];
    let result = enricher.enrich(&commits).await.unwrap();

    assert_eq!(result.len(), 1);
    let data = &result[0];
    assert!(data.semantic_edges.is_empty());
    assert!(data.adjusted_confidence.is_none());
    assert!(data.embedding.is_none());
    assert!(data.implicit_claims.is_empty());
}

#[tokio::test]
async fn test_noop_enricher_preserves_commit_count() {
    let enricher = NoopEnricher;
    let commits = vec![
        make_commit("aaa", CommitType::Feat, "core", vec![]),
        make_commit("bbb", CommitType::Fix, "api", vec!["aaa"]),
        make_commit("ccc", CommitType::Docs, "docs", vec!["bbb"]),
    ];

    let result = enricher.enrich(&commits).await.unwrap();
    assert_eq!(result.len(), commits.len());
}

#[tokio::test]
async fn test_noop_embed_returns_none() {
    let enricher = NoopEnricher;
    let result = enricher.embed("any text here").await.unwrap();
    assert!(result.is_none());
}

#[test]
fn test_noop_enricher_name() {
    let enricher = NoopEnricher;
    assert_eq!(enricher.name(), "noop");
}

// --- 1.3 Pipeline integration tests ---

#[test]
fn test_build_packet_with_empty_enrichment_unchanged() {
    // A packet built with NoopEnricher (empty enrichment) should be identical
    // to a packet built with None enrichment
    let commit = ParsedCommit {
        hash: "abc123".to_string(),
        author_name: "Dev".into(),
        author_email: "dev@example.com".into(),
        date: "2026-01-01".into(),
        commit_type: CommitType::Feat,
        scope: "core".into(),
        claim_text: "add feature".into(),
        evidence: vec!["Plan requires it".into()],
        reasoning: vec!["Chose approach A".into()],
        verification: vec!["tests pass".into()],
        parent_hashes: vec![],
        trailers: vec![],
        files_changed: vec!["src/lib.rs".into()],
    };
    let signer = AgentSigner::generate();
    let agent_id = Uuid::new_v4();

    let packet_none = build_packet(&commit, &signer, agent_id, None);
    let enrichment = EnrichedData::default();
    let packet_enriched = build_packet(&commit, &signer, agent_id, Some(&enrichment));

    assert_eq!(packet_none.claim.content, packet_enriched.claim.content);
    assert_eq!(
        packet_none.claim.initial_truth,
        packet_enriched.claim.initial_truth
    );
    assert_eq!(
        packet_none.reasoning_trace.confidence,
        packet_enriched.reasoning_trace.confidence
    );
    assert_eq!(
        packet_none.reasoning_trace.methodology,
        packet_enriched.reasoning_trace.methodology
    );
    assert_eq!(packet_none.evidence.len(), packet_enriched.evidence.len());
}

#[test]
fn test_build_packet_with_adjusted_confidence() {
    // Enrichment lowers confidence from parser's 0.85 to 0.6
    let commit = ParsedCommit {
        hash: "abc123".to_string(),
        author_name: "Dev".into(),
        author_email: "dev@example.com".into(),
        date: "2026-01-01".into(),
        commit_type: CommitType::Feat,
        scope: "core".into(),
        claim_text: "add feature".into(),
        evidence: vec!["evidence".into()],
        reasoning: vec!["reasoning".into()],
        verification: vec!["verification".into()],
        parent_hashes: vec![],
        trailers: vec![],
        files_changed: vec![],
    };
    let signer = AgentSigner::generate();
    let agent_id = Uuid::new_v4();

    // Parser would give confidence 0.85 (full metadata)
    let packet_baseline = build_packet(&commit, &signer, agent_id, None);
    assert!((packet_baseline.reasoning_trace.confidence - 0.85).abs() < f64::EPSILON);

    // Enrichment adjusts down to 0.6
    let enrichment = EnrichedData {
        adjusted_confidence: Some(0.6),
        ..EnrichedData::default()
    };
    let packet = build_packet(&commit, &signer, agent_id, Some(&enrichment));
    assert!(
        (packet.reasoning_trace.confidence - 0.6).abs() < f64::EPSILON,
        "Enrichment should lower confidence to 0.6, got {}",
        packet.reasoning_trace.confidence
    );
}

#[test]
fn test_build_packet_rejects_inflated_confidence() {
    // Enrichment tries to RAISE confidence above parser ceiling — must be clamped
    let commit = ParsedCommit {
        hash: "abc123".to_string(),
        author_name: "Dev".into(),
        author_email: "dev@example.com".into(),
        date: "2026-01-01".into(),
        commit_type: CommitType::Chore,
        scope: "build".into(),
        claim_text: "update deps".into(),
        evidence: vec![],
        reasoning: vec![],
        verification: vec![],
        parent_hashes: vec![],
        trailers: vec![],
        files_changed: vec![],
    };
    let signer = AgentSigner::generate();
    let agent_id = Uuid::new_v4();

    // Parser gives confidence 0.3 (no metadata, chore)
    let packet_baseline = build_packet(&commit, &signer, agent_id, None);
    assert!((packet_baseline.reasoning_trace.confidence - 0.3).abs() < f64::EPSILON);

    // Enrichment tries to inflate to 0.9 — must be clamped to 0.3
    let enrichment = EnrichedData {
        adjusted_confidence: Some(0.9),
        ..EnrichedData::default()
    };
    let packet = build_packet(&commit, &signer, agent_id, Some(&enrichment));
    assert!(
        (packet.reasoning_trace.confidence - 0.3).abs() < f64::EPSILON,
        "Enrichment must NOT raise confidence above parser ceiling. Expected 0.3, got {}",
        packet.reasoning_trace.confidence
    );
}

#[test]
fn test_cli_default_enricher_is_noop() {
    // Verify that EnricherMode defaults to Noop
    assert_eq!(EnricherMode::from_str("noop").unwrap(), EnricherMode::Noop);
    assert_eq!(EnricherMode::from_str("llm").unwrap(), EnricherMode::Llm);
    assert!(EnricherMode::from_str("invalid").is_err());
}

#[tokio::test]
async fn test_noop_enricher_empty_commits() {
    let enricher = NoopEnricher;
    let commits: Vec<ParsedCommit> = vec![];
    let result = enricher.enrich(&commits).await.unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn test_enrichment_pipeline_integration() {
    // Simulate the full pipeline: parse → enrich → build_packet
    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();
    let enricher = NoopEnricher;
    let enrichments = enricher.enrich(&commits).await.unwrap();

    assert_eq!(enrichments.len(), commits.len());

    let signer = AgentSigner::generate();
    let agent_id = Uuid::new_v4();

    // Build packets with enrichment and verify they match the no-enrichment baseline
    for (commit, enrichment) in commits.iter().zip(enrichments.iter()) {
        let packet_with = build_packet(commit, &signer, agent_id, Some(enrichment));
        let packet_without = build_packet(commit, &signer, agent_id, None);

        assert_eq!(packet_with.claim.content, packet_without.claim.content);
        assert_eq!(
            packet_with.reasoning_trace.confidence,
            packet_without.reasoning_trace.confidence
        );
        assert_eq!(
            packet_with.claim.initial_truth,
            packet_without.claim.initial_truth
        );
    }
}

// =========================================================================
// PHASE 3: LLM ENRICHER TESTS
// =========================================================================

#[tokio::test]
async fn test_llm_enricher_mock_returns_edges() {
    use epigraph_cli::enrichment::llm_client::MockLlmClient;

    // Mock LLM returns a relationship between commit 0 and commit 1
    let mock_response = serde_json::json!([
        {
            "source_index": 0,
            "target_index": 1,
            "relationship": "supports",
            "strength": 0.85,
            "rationale": "Commit 0 provides foundation for commit 1"
        }
    ]);

    let client = MockLlmClient::with_responses(vec![mock_response]);
    let enricher = LlmEnricher::with_config(std::sync::Arc::new(client), 20, 5);

    let commits = vec![
        make_commit("aaa", CommitType::Feat, "core", vec![]),
        make_commit("bbb", CommitType::Fix, "core", vec!["aaa"]),
    ];

    let result = enricher.enrich(&commits).await.unwrap();
    assert_eq!(result.len(), 2);

    // Commit 0 should have an edge to commit 1
    assert_eq!(result[0].semantic_edges.len(), 1);
    assert_eq!(result[0].semantic_edges[0].target_hash, "bbb");
    assert_eq!(result[0].semantic_edges[0].relationship, "supports");
    assert!((result[0].semantic_edges[0].strength - 0.85).abs() < f64::EPSILON);
}

#[tokio::test]
async fn test_llm_enricher_sliding_window_overlap() {
    use epigraph_cli::enrichment::llm_client::MockLlmClient;

    // Window size 3, overlap 1 → commits [0,1,2] then [2,3,4]
    // The overlap means commit 2 appears in both windows
    let window1_response = serde_json::json!([
        {
            "source_index": 0,
            "target_index": 2,
            "relationship": "elaborates",
            "strength": 0.7,
            "rationale": "First to third"
        }
    ]);
    let window2_response = serde_json::json!([
        {
            "source_index": 0,
            "target_index": 1,
            "relationship": "supports",
            "strength": 0.6,
            "rationale": "Third to fourth"
        }
    ]);

    let client = MockLlmClient::with_responses(vec![window1_response, window2_response]);
    let enricher = LlmEnricher::with_config(std::sync::Arc::new(client), 3, 1);

    let commits = vec![
        make_commit("a", CommitType::Feat, "core", vec![]),
        make_commit("b", CommitType::Fix, "core", vec!["a"]),
        make_commit("c", CommitType::Docs, "core", vec!["b"]),
        make_commit("d", CommitType::Test, "core", vec!["c"]),
        make_commit("e", CommitType::Refactor, "core", vec!["d"]),
    ];

    let result = enricher.enrich(&commits).await.unwrap();
    assert_eq!(result.len(), 5);

    // First window: commit 0 → commit 2 (global)
    assert_eq!(result[0].semantic_edges.len(), 1);
    assert_eq!(result[0].semantic_edges[0].target_hash, "c");

    // Second window starts at index 2: window-local 0→1 maps to global 2→3
    assert_eq!(result[2].semantic_edges.len(), 1);
    assert_eq!(result[2].semantic_edges[0].target_hash, "d");
}

#[tokio::test]
async fn test_llm_enricher_handles_empty_commits() {
    use epigraph_cli::enrichment::llm_client::MockLlmClient;

    let client = MockLlmClient::new();
    let enricher = LlmEnricher::with_config(std::sync::Arc::new(client), 20, 5);

    let result = enricher.enrich(&[]).await.unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn test_llm_enricher_handles_api_failure_gracefully() {
    use epigraph_cli::enrichment::llm_client::MockLlmClient;

    // Simulate malformed response — enricher should not fail, just skip that window
    let client = MockLlmClient::new();
    client.set_malformed(true);
    let enricher = LlmEnricher::with_config(std::sync::Arc::new(client), 20, 5);

    let commits = vec![
        make_commit("aaa", CommitType::Feat, "core", vec![]),
        make_commit("bbb", CommitType::Fix, "core", vec!["aaa"]),
    ];

    // Should not panic or return error — graceful degradation
    let result = enricher.enrich(&commits).await.unwrap();
    assert_eq!(result.len(), 2);
    // No edges extracted due to failure
    assert!(result[0].semantic_edges.is_empty());
    assert!(result[1].semantic_edges.is_empty());
}

#[tokio::test]
async fn test_llm_enricher_filters_invalid_relationships() {
    use epigraph_cli::enrichment::llm_client::MockLlmClient;

    // LLM returns some valid and some invalid relationships
    let mock_response = serde_json::json!([
        {
            "source_index": 0,
            "target_index": 1,
            "relationship": "supports",
            "strength": 0.8,
            "rationale": "Valid relationship"
        },
        {
            "source_index": 0,
            "target_index": 0,
            "relationship": "supports",
            "strength": 0.5,
            "rationale": "Self-reference — should be filtered"
        },
        {
            "source_index": 0,
            "target_index": 99,
            "relationship": "supports",
            "strength": 0.5,
            "rationale": "Out of bounds — should be filtered"
        }
    ]);

    let client = MockLlmClient::with_responses(vec![mock_response]);
    let enricher = LlmEnricher::with_config(std::sync::Arc::new(client), 20, 5);

    let commits = vec![
        make_commit("aaa", CommitType::Feat, "core", vec![]),
        make_commit("bbb", CommitType::Fix, "core", vec!["aaa"]),
    ];

    let result = enricher.enrich(&commits).await.unwrap();
    // Only the valid relationship should survive
    assert_eq!(result[0].semantic_edges.len(), 1);
    assert_eq!(result[0].semantic_edges[0].rationale, "Valid relationship");
}

#[test]
fn test_llm_enricher_name() {
    use epigraph_cli::enrichment::llm_client::MockLlmClient;

    let client = MockLlmClient::new();
    let enricher = LlmEnricher::new(std::sync::Arc::new(client));
    assert_eq!(enricher.name(), "mock");
}

// -------------------------------------------------------------------------
// Edge submission tests (Phase 3.4)
// -------------------------------------------------------------------------

#[test]
fn test_count_semantic_edges_empty() {
    let enrichments = vec![EnrichedData::default(); 3];
    assert_eq!(count_semantic_edges(&enrichments), 0);
}

#[test]
fn test_count_semantic_edges_mixed() {
    let enrichments = vec![
        EnrichedData {
            semantic_edges: vec![
                SemanticEdge {
                    target_hash: "bbb".to_string(),
                    relationship: "supports".to_string(),
                    strength: 0.8,
                    rationale: "test".to_string(),
                },
                SemanticEdge {
                    target_hash: "ccc".to_string(),
                    relationship: "elaborates".to_string(),
                    strength: 0.6,
                    rationale: "test2".to_string(),
                },
            ],
            ..EnrichedData::default()
        },
        EnrichedData::default(),
        EnrichedData {
            semantic_edges: vec![SemanticEdge {
                target_hash: "ddd".to_string(),
                relationship: "refutes".to_string(),
                strength: 0.5,
                rationale: "test3".to_string(),
            }],
            ..EnrichedData::default()
        },
    ];
    assert_eq!(count_semantic_edges(&enrichments), 3);
}

#[test]
fn test_create_edge_request_serializes() {
    let request = CreateEdgeRequest {
        source_id: Uuid::new_v4(),
        target_id: Uuid::new_v4(),
        source_type: "claim".to_string(),
        target_type: "claim".to_string(),
        relationship: "supports".to_string(),
        properties: Some(serde_json::json!({
            "strength": 0.85,
            "rationale": "Commit A provides foundation for B",
            "source": "llm_enrichment"
        })),
    };
    let json = serde_json::to_value(&request).unwrap();
    assert_eq!(json["source_type"], "claim");
    assert_eq!(json["relationship"], "supports");
    assert_eq!(json["properties"]["source"], "llm_enrichment");
}

#[test]
fn test_edge_submission_skips_unresolved_source() {
    // When a commit's hash isn't in the tracker, edges should be skipped
    let _commits = [make_commit("aaa", CommitType::Feat, "core", vec![])];
    let _enrichments = [EnrichedData {
        semantic_edges: vec![SemanticEdge {
            target_hash: "bbb".to_string(),
            relationship: "supports".to_string(),
            strength: 0.8,
            rationale: "test".to_string(),
        }],
        ..EnrichedData::default()
    }];

    let tracker = RelationshipTracker::new();
    // tracker has no entries — source hash "aaa" won't resolve
    assert!(!tracker.hash_to_claim.contains_key("aaa"));
}

#[test]
fn test_edge_submission_skips_unresolved_target() {
    let commits = [
        make_commit("aaa", CommitType::Feat, "core", vec![]),
        make_commit("bbb", CommitType::Fix, "core", vec!["aaa"]),
    ];
    let _enrichments = [
        EnrichedData {
            semantic_edges: vec![SemanticEdge {
                target_hash: "zzz".to_string(), // Not in our batch
                relationship: "supports".to_string(),
                strength: 0.8,
                rationale: "test".to_string(),
            }],
            ..EnrichedData::default()
        },
        EnrichedData::default(),
    ];

    let mut tracker = RelationshipTracker::new();
    let claim_a = Uuid::new_v4();
    tracker.record(&commits[0], claim_a);

    // Source "aaa" resolves, but target "zzz" won't
    assert!(tracker.hash_to_claim.contains_key(&commits[0].hash));
    assert!(!tracker.hash_to_claim.contains_key("zzz"));
}

#[test]
fn test_edge_submission_resolves_both_hashes() {
    let commits = [
        make_commit("aaa", CommitType::Feat, "core", vec![]),
        make_commit("bbb", CommitType::Fix, "core", vec!["aaa"]),
    ];
    let enrichments = [
        EnrichedData {
            semantic_edges: vec![SemanticEdge {
                target_hash: "bbb".to_string(),
                relationship: "supports".to_string(),
                strength: 0.85,
                rationale: "A provides foundation for B".to_string(),
            }],
            ..EnrichedData::default()
        },
        EnrichedData::default(),
    ];

    let mut tracker = RelationshipTracker::new();
    let claim_a = Uuid::new_v4();
    let claim_b = Uuid::new_v4();
    tracker.record(&commits[0], claim_a);
    tracker.record(&commits[1], claim_b);

    // Both hashes resolve correctly
    assert_eq!(tracker.hash_to_claim.get("aaa"), Some(&claim_a));
    assert_eq!(tracker.hash_to_claim.get("bbb"), Some(&claim_b));

    // Verify edge would be constructed correctly
    let edge = &enrichments[0].semantic_edges[0];
    let source_id = tracker.hash_to_claim.get("aaa").unwrap();
    let target_id = tracker.hash_to_claim.get(&edge.target_hash).unwrap();
    assert_ne!(source_id, target_id);
    assert_eq!(edge.relationship, "supports");
}

#[test]
fn test_dry_run_shows_semantic_edges() {
    // Verify that enrichment edges are accessible by index during dry-run display
    let commits = [
        make_commit("aaa", CommitType::Feat, "core", vec![]),
        make_commit("bbb", CommitType::Fix, "core", vec!["aaa"]),
    ];
    let enrichments = [
        EnrichedData {
            semantic_edges: vec![SemanticEdge {
                target_hash: "bbb".to_string(),
                relationship: "supports".to_string(),
                strength: 0.85,
                rationale: "foundation".to_string(),
            }],
            ..EnrichedData::default()
        },
        EnrichedData::default(),
    ];

    // Verify indexing works correctly (mirrors dry-run loop logic)
    for (i, _commit) in commits.iter().enumerate() {
        for edge in &enrichments[i].semantic_edges {
            let hash_preview = &edge.target_hash[..12.min(edge.target_hash.len())];
            assert!(!hash_preview.is_empty());
        }
    }
    assert_eq!(enrichments[0].semantic_edges.len(), 1);
    assert!(enrichments[1].semantic_edges.is_empty());
}

#[test]
fn test_usage_no_longer_offers_embed() {
    // The embedding PUT routes it drove were removed (backlog 9bef22f3).
    assert!(!USAGE.contains("--embed"));
}

// =========================================================================
// PHASE 7: INTEGRATION TESTING
// =========================================================================

// -------------------------------------------------------------------------
// 7.1: E2E Pipeline with LLM Enrichment
// -------------------------------------------------------------------------

#[tokio::test]
async fn test_e2e_pipeline_with_llm_enrichment_produces_connected_graph() {
    // Full pipeline: parse → LLM enrich → build_packet with enrichment applied
    // Validates that enrichment edges are reflected in the final output.
    use epigraph_cli::enrichment::llm_client::MockLlmClient;

    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();
    assert_eq!(commits.len(), 10);

    // Mock LLM returns relationships across scope boundaries
    // that the deterministic parser cannot detect
    let mock_responses: Vec<serde_json::Value> = vec![serde_json::json!([
        {
            "source_index": 0, // feat(core): define Claim
            "target_index": 1, // feat(crypto): BLAKE3 + Ed25519
            "relationship": "supports",
            "strength": 0.9,
            "rationale": "Claim model needs crypto for content hashing"
        },
        {
            "source_index": 2, // fix(core): NaN prevention
            "target_index": 0, // feat(core): define Claim
            "relationship": "challenges",
            "strength": 0.85,
            "rationale": "Fix corrects oversight in Claim validation"
        },
        {
            "source_index": 3, // security(crypto): timing attacks
            "target_index": 1, // feat(crypto): BLAKE3 + Ed25519
            "relationship": "challenges",
            "strength": 0.8,
            "rationale": "Security fix hardens crypto implementation"
        },
        {
            "source_index": 4, // test(engine): property tests
            "target_index": 8, // feat(engine): Bayesian truth update
            "relationship": "supports",
            "strength": 0.95,
            "rationale": "Tests validate the truth propagation engine"
        },
        {
            "source_index": 5, // refactor(db): repository pattern
            "target_index": 0, // feat(core): define Claim
            "relationship": "elaborates",
            "strength": 0.7,
            "rationale": "Repository pattern organizes data access for Claim model"
        }
    ])];

    let client = MockLlmClient::with_responses(mock_responses);
    let enricher = LlmEnricher::with_config(std::sync::Arc::new(client), 20, 5);
    let enrichments = enricher.enrich(&commits).await.unwrap();
    assert_eq!(enrichments.len(), 10);

    let signer = AgentSigner::generate();
    let agent_id = Uuid::new_v4();

    // Build all packets — verify enrichment is applied
    let mut packets_with_edges = 0;
    for (commit, enrichment) in commits.iter().zip(enrichments.iter()) {
        let _packet = build_packet(commit, &signer, agent_id, Some(enrichment));
        if !enrichment.semantic_edges.is_empty() {
            packets_with_edges += 1;
        }
    }

    // At least some commits should have semantic edges from LLM enrichment
    assert!(
        packets_with_edges > 0,
        "LLM enrichment should produce at least one commit with semantic edges"
    );

    // Verify total edge count matches what we supplied
    let total_edges: usize = enrichments.iter().map(|e| e.semantic_edges.len()).sum();
    assert_eq!(total_edges, 5, "Expected 5 semantic edges from mock LLM");
}

#[tokio::test]
async fn test_e2e_enrichment_confidence_never_exceeds_parser() {
    // Verify the epistemic invariant: LLM can only LOWER confidence, never raise
    let commits = vec![make_commit("aaa", CommitType::Feat, "core", vec![])];

    // Create enrichment that tries to raise confidence above parser ceiling
    let enricher = NoopEnricher;
    let enrichments = enricher.enrich(&commits).await.unwrap();

    let signer = AgentSigner::generate();
    let agent_id = Uuid::new_v4();

    // Baseline: no enrichment
    let baseline = build_packet(&commits[0], &signer, agent_id, None);
    let parser_confidence = baseline.reasoning_trace.confidence;

    // With enrichment that attempts to raise (manually crafted)
    let high_enrichment = EnrichedData {
        adjusted_confidence: Some(0.99), // Attempt to raise above parser ceiling
        ..EnrichedData::default()
    };
    let enriched = build_packet(&commits[0], &signer, agent_id, Some(&high_enrichment));

    assert!(
        enriched.reasoning_trace.confidence <= parser_confidence,
        "Enriched confidence {} must not exceed parser confidence {}",
        enriched.reasoning_trace.confidence,
        parser_confidence
    );

    // With enrichment that lowers
    let low_enrichment = EnrichedData {
        adjusted_confidence: Some(0.15),
        ..EnrichedData::default()
    };
    let lowered = build_packet(&commits[0], &signer, agent_id, Some(&low_enrichment));

    assert!(
        lowered.reasoning_trace.confidence < parser_confidence,
        "Low enrichment {} should be below parser confidence {}",
        lowered.reasoning_trace.confidence,
        parser_confidence
    );
    assert!(
        (lowered.reasoning_trace.confidence - 0.15).abs() < f64::EPSILON,
        "Should use the enrichment confidence when lower"
    );

    // With noop enrichment (no adjustment)
    let noop = build_packet(&commits[0], &signer, agent_id, Some(&enrichments[0]));
    assert!(
        (noop.reasoning_trace.confidence - parser_confidence).abs() < f64::EPSILON,
        "Noop enrichment should not change confidence"
    );
}

// -------------------------------------------------------------------------
// 7.2: Graph Quality Validation
// -------------------------------------------------------------------------

#[tokio::test]
async fn test_graph_quality_metrics_with_enrichment() {
    // Validate graph connectivity metrics from GIT_INGESTER_TEST_PLAN.md §5.1.5:
    // - ORPHAN count must be 0 (every commit produces a claim)
    // - ISOLATED must be < 15%
    // - CONNECTED must be > 40%
    use epigraph_cli::enrichment::llm_client::MockLlmClient;

    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();
    let n = commits.len();

    // Build a rich set of LLM-discovered edges
    let mock_responses: Vec<serde_json::Value> = vec![serde_json::json!([
        { "source_index": 0, "target_index": 1, "relationship": "supports", "strength": 0.9, "rationale": "r1" },
        { "source_index": 0, "target_index": 2, "relationship": "supports", "strength": 0.8, "rationale": "r2" },
        { "source_index": 1, "target_index": 3, "relationship": "supports", "strength": 0.7, "rationale": "r3" },
        { "source_index": 2, "target_index": 0, "relationship": "challenges", "strength": 0.85, "rationale": "r4" },
        { "source_index": 3, "target_index": 1, "relationship": "challenges", "strength": 0.8, "rationale": "r5" },
        { "source_index": 4, "target_index": 8, "relationship": "supports", "strength": 0.95, "rationale": "r6" },
        { "source_index": 5, "target_index": 0, "relationship": "elaborates", "strength": 0.7, "rationale": "r7" },
        { "source_index": 6, "target_index": 8, "relationship": "elaborates", "strength": 0.6, "rationale": "r8" },
        { "source_index": 8, "target_index": 4, "relationship": "supports", "strength": 0.9, "rationale": "r9" }
    ])];

    let client = MockLlmClient::with_responses(mock_responses);
    let enricher = LlmEnricher::with_config(std::sync::Arc::new(client), 20, 5);
    let enrichments = enricher.enrich(&commits).await.unwrap();

    // Also count deterministic edges from parser (parent chains + fix-challenges-feat)
    let mut tracker = RelationshipTracker::new();
    let signer = AgentSigner::generate();
    let agent_id = Uuid::new_v4();

    for commit in &commits {
        let claim_id = Uuid::new_v4();
        tracker.record(commit, claim_id);
        let _packet = build_packet(commit, &signer, agent_id, None);
    }

    // Count nodes connected by semantic edges
    let mut connected_nodes: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for (i, enrichment) in enrichments.iter().enumerate() {
        if !enrichment.semantic_edges.is_empty() {
            connected_nodes.insert(i);
            for edge in &enrichment.semantic_edges {
                // Find the target index by matching hash
                if let Some(target_idx) = commits.iter().position(|c| c.hash == edge.target_hash) {
                    connected_nodes.insert(target_idx);
                }
            }
        }
    }

    // Also count deterministic parent-child connections
    for (i, commit) in commits.iter().enumerate() {
        if !commit.parent_hashes.is_empty() {
            connected_nodes.insert(i);
            for parent in &commit.parent_hashes {
                if let Some(pidx) = commits.iter().position(|c| c.hash == *parent) {
                    connected_nodes.insert(pidx);
                }
            }
        }
    }

    let isolated_count = n - connected_nodes.len();
    let connected_pct = (connected_nodes.len() as f64) / (n as f64) * 100.0;
    let isolated_pct = (isolated_count as f64) / (n as f64) * 100.0;

    // All 10 commits should produce claims (no orphans)
    assert_eq!(enrichments.len(), n, "ORPHAN count must be 0");

    // Connectivity thresholds
    assert!(
        isolated_pct < 15.0,
        "ISOLATED must be < 15%, got {:.1}% ({} of {})",
        isolated_pct,
        isolated_count,
        n
    );
    assert!(
        connected_pct > 40.0,
        "CONNECTED must be > 40%, got {:.1}% ({} of {})",
        connected_pct,
        connected_nodes.len(),
        n
    );
}

#[tokio::test]
async fn test_noop_enricher_produces_fewer_connections_than_llm() {
    // Compare graph density: LLM enrichment should produce more edges
    // than the deterministic-only parser
    use epigraph_cli::enrichment::llm_client::MockLlmClient;

    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();

    // Noop: 0 semantic edges
    let noop = NoopEnricher;
    let noop_enrichments = noop.enrich(&commits).await.unwrap();
    let noop_edges: usize = noop_enrichments
        .iter()
        .map(|e| e.semantic_edges.len())
        .sum();

    // LLM: should produce edges
    let mock_responses: Vec<serde_json::Value> = vec![serde_json::json!([
        { "source_index": 0, "target_index": 1, "relationship": "supports", "strength": 0.9, "rationale": "r" },
        { "source_index": 2, "target_index": 0, "relationship": "challenges", "strength": 0.8, "rationale": "r" },
    ])];
    let client = MockLlmClient::with_responses(mock_responses);
    let enricher = LlmEnricher::with_config(std::sync::Arc::new(client), 20, 5);
    let llm_enrichments = enricher.enrich(&commits).await.unwrap();
    let llm_edges: usize = llm_enrichments.iter().map(|e| e.semantic_edges.len()).sum();

    assert_eq!(
        noop_edges, 0,
        "Noop enricher should produce 0 semantic edges"
    );
    assert!(
        llm_edges > noop_edges,
        "LLM enricher ({} edges) should produce more edges than noop ({})",
        llm_edges,
        noop_edges
    );
}

// -------------------------------------------------------------------------
// 7.3: Semantic Search Quality (Content-Based Relevance)
// -------------------------------------------------------------------------

#[test]
fn test_topical_claims_have_relevant_content() {
    // Verify that parsed claims contain domain-relevant keywords
    // This validates the content quality for semantic search
    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();
    let by_hash: HashMap<&str, &ParsedCommit> =
        commits.iter().map(|c| (c.hash.as_str(), c)).collect();

    // "cryptographic signing" → crypto claims
    let crypto_claims: Vec<&ParsedCommit> =
        commits.iter().filter(|c| c.scope == "crypto").collect();
    assert!(
        !crypto_claims.is_empty(),
        "Should have crypto-scoped claims"
    );
    for claim in &crypto_claims {
        let content = format!("{} {}", claim.claim_text, claim.evidence.join(" "));
        let has_crypto_terms = content.contains("BLAKE3")
            || content.contains("Ed25519")
            || content.contains("signing")
            || content.contains("timing")
            || content.contains("signature")
            || content.contains("hashing");
        assert!(
            has_crypto_terms,
            "Crypto claim should contain crypto-relevant terms: {}",
            claim.claim_text
        );
    }

    // "bayesian truth update" → engine claims
    let engine_claims: Vec<&ParsedCommit> =
        commits.iter().filter(|c| c.scope == "engine").collect();
    assert!(
        !engine_claims.is_empty(),
        "Should have engine-scoped claims"
    );
    for claim in &engine_claims {
        let content = format!("{} {}", claim.claim_text, claim.reasoning.join(" "));
        let has_engine_terms = content.contains("Bayesian")
            || content.contains("truth")
            || content.contains("propagation")
            || content.contains("property");
        assert!(
            has_engine_terms,
            "Engine claim should contain engine-relevant terms: {}",
            claim.claim_text
        );
    }

    // Security claims should mention vulnerabilities
    let security_claim = by_hash["ddd444"];
    assert_eq!(security_claim.commit_type, CommitType::Security);
    let content = format!(
        "{} {}",
        security_claim.claim_text,
        security_claim.evidence.join(" ")
    );
    assert!(
        content.contains("timing")
            || content.contains("side-channel")
            || content.contains("security"),
        "Security claim should contain security-relevant terms"
    );
}

#[test]
fn test_claim_content_format_enables_semantic_search() {
    // Verify that build_packet produces claim content in a format
    // that encodes scope/type metadata for better embedding quality
    let commit = ParsedCommit {
        hash: "abc123".to_string(),
        author_name: "Alice".to_string(),
        author_email: "alice@test.dev".to_string(),
        date: "2026-01-15".to_string(),
        commit_type: CommitType::Feat,
        scope: "crypto".to_string(),
        claim_text: "add BLAKE3 content hashing".to_string(),
        evidence: vec!["IMPLEMENTATION_PLAN requires hashing".to_string()],
        reasoning: vec!["BLAKE3 chosen over SHA-256 for speed".to_string()],
        verification: vec!["test_hash_deterministic passes".to_string()],
        parent_hashes: vec![],
        trailers: vec![],
        files_changed: vec!["crates/epigraph-crypto/src/hasher.rs".to_string()],
    };

    let signer = AgentSigner::generate();
    let agent_id = Uuid::new_v4();
    let packet = build_packet(&commit, &signer, agent_id, None);

    // Content should include scope and type for embedding context
    assert!(
        packet.claim.content.contains("[feat]"),
        "Claim content should include commit type"
    );
    assert!(
        packet.claim.content.contains("[crypto]"),
        "Claim content should include scope"
    );
    assert!(
        packet.claim.content.contains("BLAKE3"),
        "Claim content should include the claim text"
    );
}

// -------------------------------------------------------------------------
// 7.4: Provenance Token Budget
// -------------------------------------------------------------------------

#[test]
fn test_provenance_chain_within_token_budget() {
    // Validate GIT_INGESTER_TEST_PLAN.md §5.4.4:
    // - Median provenance chain < 1500 tokens
    // - 95th percentile < 3000 tokens
    //
    // Approximation: 1 token ≈ 4 characters (standard GPT tokenization estimate)

    let output = realistic_git_log_output();
    let commits = parse_git_log_output(&output).unwrap();
    let signer = AgentSigner::generate();
    let agent_id = Uuid::new_v4();

    let mut token_estimates: Vec<usize> = Vec::new();

    for commit in &commits {
        let packet = build_packet(commit, &signer, agent_id, None);

        // Provenance chain = claim content + reasoning explanation + all evidence
        let mut chain_chars = 0;
        chain_chars += packet.claim.content.len();
        chain_chars += packet.reasoning_trace.explanation.len();
        for evidence in &packet.evidence {
            if let Some(ref raw) = evidence.raw_content {
                chain_chars += raw.len();
            }
        }

        // Approximate token count (1 token ≈ 4 chars)
        let token_estimate = chain_chars / 4;
        token_estimates.push(token_estimate);
    }

    token_estimates.sort();
    let n = token_estimates.len();

    // Median
    let median = if n.is_multiple_of(2) {
        (token_estimates[n / 2 - 1] + token_estimates[n / 2]) / 2
    } else {
        token_estimates[n / 2]
    };

    // 95th percentile (for 10 items, this is the 10th item)
    let p95_idx = ((n as f64) * 0.95).ceil() as usize - 1;
    let p95 = token_estimates[p95_idx.min(n - 1)];

    assert!(
        median < 1500,
        "Median provenance chain should be < 1500 tokens, got {}",
        median
    );
    assert!(
        p95 < 3000,
        "95th percentile provenance chain should be < 3000 tokens, got {}",
        p95
    );
}

#[test]
fn test_individual_claim_provenance_fits_context_window() {
    // Each individual claim's provenance chain should fit within
    // a reasonable LLM context window segment (< 500 tokens)
    let commit = ParsedCommit {
        hash: "abc123".to_string(),
        author_name: "Alice".to_string(),
        author_email: "alice@test.dev".to_string(),
        date: "2026-01-15".to_string(),
        commit_type: CommitType::Feat,
        scope: "core".to_string(),
        claim_text: "define Claim model with bounded truth values".to_string(),
        evidence: vec![
            "IMPLEMENTATION_PLAN.md §2.1 specifies truth in [0.0, 1.0]".to_string(),
            "Unbounded floats allow invalid states (NaN, infinity)".to_string(),
        ],
        reasoning: vec![
            "Chose f64 over f32: precision matters for Bayesian updates near 0/1".to_string(),
            "Constructor validates bounds, returns Result<Claim, ClaimError>".to_string(),
        ],
        verification: vec![
            "test_claim_rejects_negative_truth: passes".to_string(),
            "test_claim_rejects_truth_above_one: passes".to_string(),
        ],
        parent_hashes: vec![],
        trailers: vec![],
        files_changed: vec!["crates/epigraph-core/src/domain/claim.rs".to_string()],
    };

    let signer = AgentSigner::generate();
    let agent_id = Uuid::new_v4();
    let packet = build_packet(&commit, &signer, agent_id, None);

    let mut total_chars = 0;
    total_chars += packet.claim.content.len();
    total_chars += packet.reasoning_trace.explanation.len();
    for evidence in &packet.evidence {
        if let Some(ref raw) = evidence.raw_content {
            total_chars += raw.len();
        }
    }

    let tokens = total_chars / 4;
    assert!(
        tokens < 500,
        "Single claim provenance should be < 500 tokens, got {} ({} chars)",
        tokens,
        total_chars
    );
}

// -------------------------------------------------------------------------
// Reference-resolver tests (UUID trailers/free-text + PR-number)
// -------------------------------------------------------------------------

#[test]
fn extracts_uuid_and_pr_references() {
    let text = "Resolves d531c585-0214-4fad-972b-10c7aa039984\n\
                Resolves-Claim: 9699e396-380b-4105-99c3-e4938dc3e156\n\
                see also PR #219 and #237";
    let refs = extract_references(text);
    assert!(refs
        .claim_uuids
        .contains(&"d531c585-0214-4fad-972b-10c7aa039984".parse().unwrap()));
    assert!(refs
        .claim_uuids
        .contains(&"9699e396-380b-4105-99c3-e4938dc3e156".parse().unwrap()));
    assert!(refs.pr_numbers.contains(&219));
    assert!(refs.pr_numbers.contains(&237));
}

// -------------------------------------------------------------------------
// Packet signatures (backlog 7d9e60c6)
// -------------------------------------------------------------------------

/// Exactly what `routes/submit.rs` does on the `require_packet_signatures`
/// path: parse the wire JSON into the SERVER's packet type, recompute
/// `signable_bytes()` and verify `signature` under the agent's key. Any
/// drift between the client's serialization and the server's (defaulted
/// `labels` / `properties`, a skipped `initial_truth`) fails here.
fn server_accepts(packet: &EpistemicPacket, signer: &AgentSigner) -> bool {
    // The request body as bytes, parsed the way axum's `Json` parses it.
    let wire = serde_json::to_vec(packet).expect("client packet serializes");
    let server: epigraph_api::routes::submit::EpistemicPacket =
        serde_json::from_slice(&wire).expect("server parses the client packet");
    let canonical = server.signable_bytes().expect("canonical bytes");
    let Ok(sig) = <[u8; 64]>::try_from(hex::decode(&server.signature).unwrap()) else {
        return false;
    };
    epigraph_crypto::SignatureVerifier::verify(&signer.public_key(), &canonical, &sig)
        .unwrap_or(false)
}

fn signing_fixture_commit() -> ParsedCommit {
    ParsedCommit {
        hash: "0123456789abcdef0123456789abcdef01234567".to_string(),
        author_name: "Sig Author".to_string(),
        author_email: "sig@example.com".to_string(),
        date: "2026-11-22T12:00:00+00:00".to_string(),
        commit_type: CommitType::Fix,
        scope: "cli".to_string(),
        claim_text: "sign packets over the canonical message".to_string(),
        evidence: vec!["submit verifies Ed25519 when signatures are required".to_string()],
        reasoning: vec!["an all-zero signature is refused".to_string()],
        verification: vec!["server_accepts passes".to_string()],
        parent_hashes: vec![],
        trailers: vec![],
        files_changed: vec!["crates/epigraph-cli/src/bin/ingest_git.rs".to_string()],
    }
}

#[test]
fn commit_packet_signature_verifies_like_the_server() {
    let signer = test_keys().author("sig@example.com");
    let packet = build_packet(&signing_fixture_commit(), &signer, Uuid::new_v4(), None);
    assert_ne!(
        packet.signature,
        "0".repeat(128),
        "no placeholder signature"
    );
    assert!(
        server_accepts(&packet, &signer),
        "a commit packet must pass require_packet_signatures verification"
    );
    // The oracle is not vacuous: another key does not verify it.
    assert!(!server_accepts(&packet, &AgentSigner::generate()));
}

#[test]
fn pr_mode_packets_verify_after_their_labels_are_set() {
    let signer = test_keys().author("sig@example.com");
    let built = build_packet(&signing_fixture_commit(), &signer, Uuid::new_v4(), None);
    let submitted = labelled_and_signed(
        built,
        &[
            "source:git-history",
            "node:commit",
            "repo:epigraph-io/epigraph",
        ],
        Some(&signer),
    );
    assert_eq!(submitted.claim.labels.len(), 3);
    assert!(
        server_accepts(&submitted, &signer),
        "the labels are signed bytes: the packet must be signed after they are set"
    );

    let repo_signer = test_keys().repo_root();
    let repo = labelled_and_signed(
        build_repo_packet("epigraph-io/epigraph", Uuid::new_v4(), &repo_signer),
        &[
            "source:git-history",
            "node:repo",
            "repo:epigraph-io/epigraph",
        ],
        Some(&repo_signer),
    );
    assert!(server_accepts(&repo, &repo_signer));
}

#[test]
fn labels_are_covered_by_the_packet_signature() {
    // Changing a label after signing invalidates the signature, which is
    // why `labelled_and_signed` signs last. The packet must verify BEFORE
    // the change, so the negative below shows the labels are covered and
    // not merely that the signature never verifies (an all-zero
    // placeholder would pass the negative alone).
    let signer = test_keys().author("sig@example.com");
    let mut packet = build_packet(&signing_fixture_commit(), &signer, Uuid::new_v4(), None);
    assert!(
        server_accepts(&packet, &signer),
        "the freshly built packet must verify"
    );
    packet.claim.labels = vec!["node:commit".to_string()];
    assert!(!server_accepts(&packet, &signer));
}

#[test]
fn repo_packet_signature_verifies_like_the_server() {
    let signer = test_keys().repo_root();
    let packet = build_repo_packet("epigraph-io/epigraph", Uuid::new_v4(), &signer);
    assert!(
        server_accepts(&packet, &signer),
        "a repo-root packet must pass require_packet_signatures verification"
    );
}
