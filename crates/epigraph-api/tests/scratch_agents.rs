//! Agents and agent relationships in the scratch graph (slice 1b, operator
//! ruling R1).
//!
//! Atoms are attributed to named agents instead of the bare roles `user` and
//! `assistant`, agents carry relationships to each other, and every
//! reference is checked: a write that names an agent the graph does not hold
//! is refused whole. Each test checks the stored graph, not only the reply.

use chrono::{DateTime, TimeZone, Utc};
use epigraph_api::scratch::snapshot::{decode, encode, DecodeError, FORMAT};
use epigraph_api::scratch::store::{
    agent_id, normalise_name, AgentRole, AtomKind, BatchOutcome, Evidence, NewAgent, NewAtom,
    NewRelation, ScratchStore, Seed, StoreError,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const SCOPE: &str = "0123456789ab";

fn t(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_790_000_000 + secs, 0).unwrap()
}

fn id(n: u128) -> Uuid {
    Uuid::from_u128(0xa9e7_0000_0000_0000_0000_0000_0000_0000 + n)
}

fn agent(name: &str, role: AgentRole, aliases: &[&str]) -> NewAgent {
    NewAgent {
        id: agent_id(SCOPE, name),
        display_name: name.to_string(),
        role,
        aliases: aliases.iter().map(|a| (*a).to_string()).collect(),
    }
}

fn atom(n: u128, speaker: &str, about: &[&str]) -> NewAtom {
    NewAtom {
        id: id(n),
        text: format!("Atom {n} of the fixture."),
        kind: AtomKind::Fact,
        speaker_agent: agent_id(SCOPE, speaker),
        about: about.iter().map(|a| agent_id(SCOPE, a)).collect(),
        turn: 1,
        epoch: 0,
        at: None,
        quote: None,
        evidence: vec![Evidence {
            path: "turns/1.json".into(),
            sha256: "ab".repeat(32),
            span: None,
            quote: None,
        }],
        seed: Seed {
            confidence: 0.8,
            reliability: 0.75,
        },
    }
}

fn relation(n: u128, source: &str, kind: &str, target: &str) -> NewRelation {
    NewRelation {
        id: id(1000 + n),
        source: agent_id(SCOPE, source),
        target: agent_id(SCOPE, target),
        kind: kind.to_string(),
        turn: 2,
    }
}

/// A graph holding the two speakers of the fixture chat and one person they
/// talk about.
fn people() -> ScratchStore {
    let mut s = ScratchStore::new(SCOPE, 0, t(0));
    s.put_agents(
        vec![
            agent("Rosalind", AgentRole::User, &[]),
            agent("Theo", AgentRole::Assistant, &[]),
            agent("Imogen", AgentRole::Participant, &["Immy"]),
        ],
        t(1),
    )
    .unwrap();
    s
}

#[test]
fn an_agent_id_is_the_uuidv5_of_the_scope_and_the_normalised_name() {
    // The same vector is pinned in the runner
    // (agent-runner `belief-context-agents.test.ts`), which computes the ids
    // it stores in its atoms files: the two must agree byte for byte.
    assert_eq!(
        agent_id(SCOPE, "  Caroline \t Smith "),
        Uuid::parse_str("e825e9fa-b6b3-53cf-a019-4b0a5b6a7419").unwrap()
    );
    assert_eq!(
        agent_id(SCOPE, "User"),
        Uuid::parse_str("784e9a80-caec-5fc2-a8d9-520df71c72de").unwrap()
    );
    assert_eq!(
        agent_id(SCOPE, "Zoë Ångström"),
        Uuid::parse_str("1cdf6606-6a75-5162-b719-a3927fb4ab1b").unwrap()
    );
    assert_eq!(normalise_name("  Caroline \t Smith "), "caroline smith");
    // Case and spacing do not make a new agent; the scope does.
    assert_eq!(
        agent_id(SCOPE, "CAROLINE SMITH"),
        agent_id(SCOPE, "caroline smith")
    );
    assert_ne!(
        agent_id(SCOPE, "Caroline Smith"),
        agent_id("0123456789ac", "Caroline Smith")
    );
}

#[test]
fn put_agents_is_idempotent_and_a_known_agent_only_gains_aliases() {
    let mut s = people();
    let before = s.clone();
    // A replay of the same agents changes nothing.
    let (out, updated) = s
        .put_agents(
            vec![
                agent("Rosalind", AgentRole::User, &[]),
                agent("Imogen", AgentRole::Participant, &["immy"]),
            ],
            t(5),
        )
        .unwrap();
    assert_eq!(
        (out, updated),
        (
            BatchOutcome {
                inserted: 0,
                existing: 2
            },
            0
        )
    );
    assert_eq!(s, before, "a replay must not touch the graph or built_at");

    // A new alias is added once, a differently-cased copy of a known one is not.
    let (_, updated) = s
        .put_agents(
            vec![agent("Imogen", AgentRole::Participant, &["Imo", "IMMY"])],
            t(6),
        )
        .unwrap();
    assert_eq!(updated, 1);
    let imogen = s.agent(&agent_id(SCOPE, "Imogen")).unwrap();
    assert_eq!(imogen.aliases, vec!["Immy".to_string(), "Imo".to_string()]);
    assert_eq!(imogen.display_name, "Imogen");
    assert_eq!(s.stats().agents, 3);
}

#[test]
fn put_agents_refuses_a_role_change_or_a_bad_name_and_stores_nothing_of_the_batch() {
    let mut s = people();
    let before = s.clone();
    let long = "x".repeat(81);
    for (batch, code) in [
        (
            vec![
                agent("Pemberton", AgentRole::Participant, &[]),
                agent("Theo", AgentRole::User, &[]),
            ],
            "conflict",
        ),
        (
            vec![
                agent("Pemberton", AgentRole::Participant, &[]),
                agent("   ", AgentRole::Participant, &[]),
            ],
            "invalid_value",
        ),
        (
            vec![agent(&long, AgentRole::Participant, &[])],
            "invalid_value",
        ),
        (
            vec![agent("Pemberton", AgentRole::Participant, &[""])],
            "invalid_value",
        ),
    ] {
        let err = s.put_agents(batch, t(9)).unwrap_err();
        assert_eq!(err.code(), code);
        assert!(
            !err.detail().contains("Pemberton") && !err.detail().contains("Theo"),
            "a detail never carries a name: {}",
            err.detail()
        );
    }
    assert_eq!(s, before, "a refused batch stores none of its agents");
}

#[test]
fn an_atom_must_name_stored_agents_and_a_refused_batch_stores_nothing() {
    let mut s = people();
    let before = s.clone();
    let stranger = agent_id(SCOPE, "Stranger");
    let err = s
        .put_atoms(
            vec![atom(1, "Rosalind", &[]), atom(2, "Stranger", &[])],
            t(2),
        )
        .unwrap_err();
    assert_eq!(err, StoreError::UnknownAgent(stranger));
    let err = s
        .put_atoms(vec![atom(3, "Rosalind", &["Imogen", "Stranger"])], t(2))
        .unwrap_err();
    assert_eq!(err, StoreError::UnknownAgent(stranger));
    let nine: Vec<String> = (0..9).map(|i| format!("Friend {i}")).collect();
    s.put_agents(
        nine.iter()
            .map(|n| agent(n, AgentRole::Participant, &[]))
            .collect(),
        t(3),
    )
    .unwrap();
    let before_nine = s.clone();
    let refs: Vec<&str> = nine.iter().map(String::as_str).collect();
    assert_eq!(
        s.put_atoms(vec![atom(4, "Theo", &refs)], t(4)).unwrap_err(),
        StoreError::InvalidValue("about")
    );
    assert_eq!(s, before_nine);
    assert_eq!(before.stats().atoms, 0);

    // A valid atom keeps its speaker and its subjects, once each, in order.
    s.put_atoms(
        vec![atom(5, "Theo", &["Imogen", "Rosalind", "Imogen"])],
        t(5),
    )
    .unwrap();
    let stored = s.atom(&id(5)).unwrap();
    assert_eq!(stored.speaker_agent, agent_id(SCOPE, "Theo"));
    assert_eq!(
        stored.about,
        vec![agent_id(SCOPE, "Imogen"), agent_id(SCOPE, "Rosalind")]
    );
}

#[test]
fn relate_is_idempotent_on_id_and_checks_both_ends_and_the_kind() {
    let mut s = people();
    let out = s
        .relate(
            vec![
                relation(1, "Rosalind", "friend_of", "Theo"),
                relation(2, "Imogen", "family_of", "Rosalind"),
            ],
            t(2),
        )
        .unwrap();
    assert_eq!(out.inserted, 2);
    let after = s.clone();
    assert_eq!(
        s.relate(vec![relation(1, "Rosalind", "friend_of", "Theo")], t(3))
            .unwrap(),
        BatchOutcome {
            inserted: 0,
            existing: 1
        }
    );
    assert_eq!(s, after, "a replayed relation changes nothing");

    for (bad, code) in [
        (
            relation(3, "Rosalind", "knows", "Stranger"),
            "unknown_agent",
        ),
        (relation(4, "Theo", "knows", "Theo"), "conflict"),
        (relation(5, "Theo", "Friend Of", "Imogen"), "invalid_value"),
        (
            relation(6, "Theo", "<b>friend</b>", "Imogen"),
            "invalid_value",
        ),
        (relation(7, "Theo", "", "Imogen"), "invalid_value"),
        (
            relation(8, "Theo", &"k".repeat(41), "Imogen"),
            "invalid_value",
        ),
    ] {
        // Each bad relation rides with a good one: the batch is refused whole.
        let err = s
            .relate(vec![relation(9, "Theo", "works_with", "Imogen"), bad], t(4))
            .unwrap_err();
        assert_eq!(err.code(), code);
    }
    assert_eq!(s, after);
    // Free text in the allowed shape is kept as given.
    s.relate(vec![relation(10, "Theo", "mentor_of", "Imogen")], t(5))
        .unwrap();
    assert_eq!(s.stats().relations, 3);
}

/// Hand-built snapshot bytes: `body` is the object without its closing brace
/// and `sha256` member.
fn sealed(body: &str) -> Vec<u8> {
    let whole = format!("{body}}}");
    let digest = hex::encode(Sha256::digest(whole.as_bytes()));
    format!("{body},\"sha256\":\"{digest}\"}}\n").into_bytes()
}

#[test]
fn a_format_1_snapshot_is_read_and_its_speaker_roles_become_named_role_agents() {
    // A slice-1 snapshot: atoms carry the bare `speaker` role.
    let sha = "cd".repeat(32);
    let v1 = sealed(&format!(
        r#"{{"format":1,"scope":"{SCOPE}","epoch":0,"applied_turns":[1],"atoms":[{{"id":"{a1}","text":"The user prefers tea.","kind":"preference","speaker":"user","turn":1,"epoch":0,"created_at":"2026-09-21T14:13:20.000Z","is_current":true,"superseded_by":null,"evidence":[{{"path":"turns/1.json","sha256":"{sha}"}}],"bbas":[{{"source":"{a1}","confidence":0.9,"reliability":0.95}}]}},{{"id":"{a2}","text":"The assistant suggested green tea.","kind":"observation","speaker":"assistant","turn":1,"epoch":0,"created_at":"2026-09-21T14:13:20.000Z","is_current":true,"superseded_by":null,"evidence":[],"bbas":[{{"source":"{a2}","confidence":0.5,"reliability":0.5}}]}}],"edges":[],"built_at":"2026-09-21T14:13:20.000Z""#,
        a1 = id(1),
        a2 = id(2),
    ));
    let store = decode(&v1).expect("a format-1 snapshot is still read");
    let user = agent_id(SCOPE, "User");
    let assistant = agent_id(SCOPE, "Assistant");
    assert_eq!(
        user,
        Uuid::parse_str("784e9a80-caec-5fc2-a8d9-520df71c72de").unwrap(),
        "the role agent's id is the one the runner computes for the name"
    );
    let agents: Vec<(Uuid, String, AgentRole)> = store
        .agents()
        .map(|a| (a.id, a.display_name.clone(), a.role))
        .collect();
    let mut want = vec![
        (user, "User".to_string(), AgentRole::User),
        (assistant, "Assistant".to_string(), AgentRole::Assistant),
    ];
    want.sort();
    assert_eq!(agents, want, "only the roles the atoms name, no Tool");
    assert_eq!(store.atom(&id(1)).unwrap().speaker_agent, user);
    assert_eq!(store.atom(&id(2)).unwrap().speaker_agent, assistant);
    assert_eq!(store.applied_turns().collect::<Vec<_>>(), vec![1]);

    // The next write stores format 2, which reads back to the same graph.
    let v2 = encode(&store);
    assert!(v2.starts_with(format!("{{\"format\":{FORMAT},").as_bytes()));
    assert_eq!(FORMAT, 2);
    assert_eq!(decode(&v2).unwrap(), store);
}

#[test]
fn a_later_format_or_a_dangling_agent_reference_is_refused_on_restore() {
    let v3 = sealed(&format!(
        r#"{{"format":3,"scope":"{SCOPE}","epoch":0,"applied_turns":[],"agents":[],"relations":[],"atoms":[],"edges":[],"built_at":"2026-09-21T14:13:20.000Z""#
    ));
    assert_eq!(decode(&v3), Err(DecodeError::UnsupportedFormat(3)));

    let sha = "cd".repeat(32);
    let dangling = sealed(&format!(
        r#"{{"format":2,"scope":"{SCOPE}","epoch":0,"applied_turns":[],"agents":[],"relations":[],"atoms":[{{"id":"{a1}","text":"x","kind":"fact","speaker_agent":"{ghost}","turn":1,"epoch":0,"created_at":"2026-09-21T14:13:20.000Z","is_current":true,"superseded_by":null,"evidence":[{{"path":"turns/1.json","sha256":"{sha}"}}],"bbas":[]}}],"edges":[],"built_at":"2026-09-21T14:13:20.000Z""#,
        a1 = id(1),
        ghost = agent_id(SCOPE, "Ghost"),
    ));
    assert_eq!(
        decode(&dangling),
        Err(DecodeError::Invalid("atom names a missing agent"))
    );
    let rel = sealed(&format!(
        r#"{{"format":2,"scope":"{SCOPE}","epoch":0,"applied_turns":[],"agents":[],"relations":[{{"id":"{r}","source":"{a}","target":"{b}","kind":"knows","turn":1}}],"atoms":[],"edges":[],"built_at":"2026-09-21T14:13:20.000Z""#,
        r = id(9),
        a = agent_id(SCOPE, "A"),
        b = agent_id(SCOPE, "B"),
    ));
    assert_eq!(
        decode(&rel),
        Err(DecodeError::Invalid(
            "relation endpoint names a missing agent"
        ))
    );
}

#[test]
fn agents_and_relations_survive_a_snapshot_byte_for_byte() {
    let mut s = people();
    s.relate(vec![relation(1, "Imogen", "family_of", "Rosalind")], t(2))
        .unwrap();
    s.put_atoms(vec![atom(1, "Rosalind", &["Imogen"])], t(3))
        .unwrap();
    let bytes = encode(&s);
    let back = decode(&bytes).unwrap();
    assert_eq!(back, s);
    assert_eq!(encode(&back), bytes);
}

/// Two people with no word in common with the query except a name.
fn named_graph() -> ScratchStore {
    let mut s = ScratchStore::new(SCOPE, 0, t(0));
    s.put_agents(
        vec![
            agent("Caroline", AgentRole::Participant, &[]),
            agent("Melanie", AgentRole::Participant, &["Mel"]),
        ],
        t(1),
    )
    .unwrap();
    let said = |n: u128, speaker: &str, about: &[&str], text: &str| {
        let mut a = atom(n, speaker, about);
        a.text = text.to_string();
        a
    };
    let atoms = vec![
        said(1, "Melanie", &[], "Painted a sunrise over the lake."),
        said(2, "Caroline", &["Melanie"], "Gave her a pottery book."),
        said(3, "Caroline", &[], "Went to a support group."),
    ];
    s.put_atoms(atoms, t(2)).unwrap();
    s.mark_applied(1, t(3));
    s
}

#[test]
fn a_query_naming_a_person_by_any_of_their_names_retrieves_that_persons_atoms() {
    use epigraph_api::scratch::belief::BeliefView;
    use epigraph_api::scratch::rank::digest;
    let s = named_graph();
    let view = BeliefView::compute(&s).unwrap();
    for query in ["What did Mel do?", "melanie"] {
        let d = digest(&s, &view, query, 5, 20);
        let mut hits: Vec<Uuid> = d.relevant.iter().map(|i| i.id).collect();
        hits.sort();
        assert_eq!(
            hits,
            vec![id(1), id(2)],
            "{query}: what Melanie said and what is about her, not Caroline's own atom"
        );
        let mut cands: Vec<Uuid> = s
            .candidates(query, 10, 0)
            .into_iter()
            .map(|c| c.atom.id)
            .collect();
        cands.sort();
        assert_eq!(cands, vec![id(1), id(2)], "{query}: candidates");
    }
    // A name matches on its own words only: "Caroline" finds both of her atoms.
    let d = digest(&s, &view, "caroline", 5, 20);
    let mut hits: Vec<Uuid> = d.relevant.iter().map(|i| i.id).collect();
    hits.sort();
    assert_eq!(hits, vec![id(2), id(3)]);
}

#[test]
fn the_people_slice_lists_each_person_with_eligible_relationships_and_top_atoms() {
    use epigraph_api::scratch::belief::BeliefView;
    use epigraph_api::scratch::rank::{digest, PEOPLE_TOP_ATOMS};
    use epigraph_api::scratch::store::Direction;
    let mut s = people();
    s.put_agents(vec![agent("read_csv", AgentRole::Tool, &[])], t(1))
        .unwrap();
    s.relate(
        vec![
            relation(1, "Imogen", "family_of", "Rosalind"),
            // Stated in a turn still quoted (the window starts at 9): not listed.
            NewRelation {
                turn: 9,
                ..relation(2, "Theo", "knows", "Imogen")
            },
        ],
        t(2),
    )
    .unwrap();
    let mk = |n: u128, turn: u64, kind: AtomKind, speaker: &str, about: &[&str], conf: f64| {
        let mut a = atom(n, speaker, about);
        a.turn = turn;
        a.kind = kind;
        a.seed.confidence = conf;
        a
    };
    s.put_atoms(
        vec![
            // About Imogen: four eligible, one in the window.
            mk(1, 1, AtomKind::Fact, "Rosalind", &["Imogen"], 0.5),
            mk(2, 2, AtomKind::Fact, "Theo", &["Imogen"], 0.9),
            mk(3, 3, AtomKind::Preference, "Rosalind", &["Imogen"], 0.3),
            mk(4, 3, AtomKind::Fact, "Rosalind", &["Imogen"], 0.7),
            mk(5, 9, AtomKind::Decision, "Rosalind", &["Imogen"], 1.0),
            // Said by Imogen herself: ranks after every atom about her.
            mk(6, 2, AtomKind::Decision, "Imogen", &[], 1.0),
            // A tool's observation: tools are not people.
            mk(7, 2, AtomKind::Observation, "read_csv", &[], 0.9),
        ],
        t(3),
    )
    .unwrap();
    for turn in [1, 2, 3, 9] {
        s.mark_applied(turn, t(4));
    }
    let view = BeliefView::compute(&s).unwrap();
    let d = digest(&s, &view, "", 9, 20);

    let names: Vec<(&str, usize)> = d
        .people
        .iter()
        .map(|p| (p.display_name, p.atoms_total))
        .collect();
    assert_eq!(
        names,
        vec![("Imogen", 5), ("Rosalind", 3), ("Theo", 1)],
        "most atoms first; the tool agent is not a person"
    );
    let imogen = &d.people[0];
    assert_eq!(imogen.aliases, ["Immy".to_string()]);
    let rels: Vec<(&str, Direction, &str)> = imogen
        .relations
        .iter()
        .map(|r| (r.kind, r.direction, r.other_name))
        .collect();
    assert_eq!(
        rels,
        vec![("family_of", Direction::Out, "Rosalind")],
        "the relation stated in a quoted turn is not listed"
    );
    // Top atoms: about her first (the preference, then by BetP), never the
    // window atom, and not her own decision while three atoms about her exist.
    let top: Vec<Uuid> = imogen.atoms.iter().map(|i| i.id).collect();
    assert_eq!(top.len(), PEOPLE_TOP_ATOMS);
    assert_eq!(top, vec![id(3), id(2), id(4)]);
    assert_eq!(imogen.atoms[1].about, vec!["Imogen"]);
    assert_eq!(imogen.atoms[1].speaker, "Theo");

    // Rosalind's relation shows from her side too.
    let rosalind = &d.people[1];
    assert_eq!(
        rosalind
            .relations
            .iter()
            .map(|r| (r.kind, r.direction, r.other_name))
            .collect::<Vec<_>>(),
        vec![("family_of", Direction::In, "Imogen")]
    );
    // k bounds the slice.
    assert_eq!(digest(&s, &view, "", 9, 1).people.len(), 1);
}
