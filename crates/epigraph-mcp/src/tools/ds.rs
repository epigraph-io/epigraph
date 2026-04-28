#![allow(clippy::wildcard_imports)]

use std::collections::BTreeSet;

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

use epigraph_db::{
    DivergenceRepository, FrameRepository, MassFunctionRepository, ScopedBeliefRepository,
};
use epigraph_ds::{combination, CombinationMethod, FocalElement, FrameOfDiscernment, MassFunction};

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

fn parse_combination_method(s: &str) -> Result<CombinationMethod, String> {
    match s.to_lowercase().as_str() {
        "dempster" => Ok(CombinationMethod::Dempster),
        "conjunctive" | "tbm" => Ok(CombinationMethod::Conjunctive),
        "yageropen" | "yager_open" => Ok(CombinationMethod::YagerOpen),
        "yagerclosed" | "yager_closed" => Ok(CombinationMethod::YagerClosed),
        "duboisprade" | "dubois_prade" => Ok(CombinationMethod::DuboisPrade),
        "inagaki" => Ok(CombinationMethod::Inagaki),
        other => Err(format!("unknown combination method: {other}. Options: Dempster, Conjunctive, YagerOpen, YagerClosed, DuboisPrade, Inagaki")),
    }
}

/// Parse mass JSON into a `MassFunction` using epigraph-ds's built-in parser.
fn parse_masses_json(
    frame: &FrameOfDiscernment,
    masses_json: &serde_json::Value,
) -> Result<MassFunction, McpError> {
    MassFunction::from_json_masses(frame.clone(), masses_json)
        .map_err(|e| invalid_params(format!("invalid mass function: {e}")))
}

/// Apply combination method to two mass functions via `redistribute()`.
fn combine_two(
    m1: &MassFunction,
    m2: &MassFunction,
    method: CombinationMethod,
    gamma: Option<f64>,
) -> Result<MassFunction, McpError> {
    combination::redistribute(m1, m2, method, gamma).map_err(internal_error)
}

pub async fn create_frame(
    server: &EpiGraphMcpFull,
    params: CreateFrameParams,
) -> Result<CallToolResult, McpError> {
    if params.hypotheses.len() < 2 {
        return Err(invalid_params("frame requires at least 2 hypotheses"));
    }

    // Check if parent is specified and valid
    if let Some(ref parent_id_str) = params.parent_frame_id {
        let parent_id = parse_uuid(parent_id_str)?;
        let frame = FrameRepository::create_refinement(
            &server.pool,
            parent_id,
            &params.name,
            params.description.as_deref(),
            &params.hypotheses,
        )
        .await
        .map_err(internal_error)?;

        return success_json(&CreateFrameResponse {
            frame_id: frame.id.to_string(),
            name: frame.name,
            hypotheses: frame.hypotheses,
            version: frame.version,
        });
    }

    let frame = FrameRepository::create(
        &server.pool,
        &params.name,
        params.description.as_deref(),
        &params.hypotheses,
    )
    .await
    .map_err(internal_error)?;

    success_json(&CreateFrameResponse {
        frame_id: frame.id.to_string(),
        name: frame.name,
        hypotheses: frame.hypotheses,
        version: frame.version,
    })
}

pub async fn submit_ds_evidence(
    server: &EpiGraphMcpFull,
    params: SubmitDsEvidenceParams,
) -> Result<CallToolResult, McpError> {
    let claim_id = parse_uuid(&params.claim_id)?;
    let frame_id = parse_uuid(&params.frame_id)?;
    let perspective_id = match &params.perspective_id {
        Some(s) => Some(parse_uuid(s)?),
        None => None,
    };

    let method = params
        .combination_method
        .as_deref()
        .map(parse_combination_method)
        .transpose()
        .map_err(invalid_params)?
        .unwrap_or(CombinationMethod::Dempster);
    let method_name = format!("{method:?}");

    // Get frame from DB
    let frame_row = FrameRepository::get_by_id(&server.pool, frame_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("frame {frame_id} not found")))?;

    let frame = FrameOfDiscernment::new(frame_row.name.clone(), frame_row.hypotheses.clone())
        .map_err(internal_error)?;

    // Parse and optionally discount the mass function
    let mut mass_fn = parse_masses_json(&frame, &params.masses)?;
    let reliability = params.reliability.unwrap_or(1.0).clamp(0.0, 1.0);
    if reliability < 1.0 {
        mass_fn =
            epigraph_ds::combination::discount(&mass_fn, reliability).map_err(internal_error)?;
    }

    // Ensure claim-frame assignment exists
    FrameRepository::assign_claim(
        &server.pool,
        claim_id,
        frame_id,
        Some(params.hypothesis_index),
    )
    .await
    .map_err(internal_error)?;

    let agent_id = server.agent_id().await?;

    // Store the BBA
    let masses_json = serde_json::to_value(
        mass_fn
            .masses()
            .iter()
            .map(|(fe, m)| (focal_to_key(fe), *m))
            .collect::<std::collections::HashMap<String, f64>>(),
    )
    .map_err(internal_error)?;

    let mf_id = MassFunctionRepository::store_with_perspective(
        &server.pool,
        claim_id,
        frame_id,
        Some(agent_id),
        perspective_id,
        &masses_json,
        None,
        Some(&method_name),
        None,
        None,
    )
    .await
    .map_err(internal_error)?;

    // Retrieve all BBAs for combination
    let all_bbas = MassFunctionRepository::get_for_claim_frame(&server.pool, claim_id, frame_id)
        .await
        .map_err(internal_error)?;

    // Combine all BBAs
    let gamma = params.gamma;
    let combined = if all_bbas.len() <= 1 {
        mass_fn.clone()
    } else {
        let mut mass_fns = Vec::new();
        for row in &all_bbas {
            let mf = parse_masses_json(&frame, &row.masses)?;
            mass_fns.push(mf);
        }
        let mut result = mass_fns[0].clone();
        for mf in &mass_fns[1..] {
            result = combine_two(&result, mf, method, gamma)?;
        }
        result
    };

    // Compute belief/plausibility for the hypothesis
    let target = FocalElement::positive(BTreeSet::from([params.hypothesis_index as usize]));
    let bel = epigraph_ds::measures::belief(&combined, &target);
    let pl = epigraph_ds::measures::plausibility(&combined, &target);
    let ign = pl - bel;
    let betp =
        epigraph_ds::measures::pignistic_probability(&combined, params.hypothesis_index as usize);

    let conflict = combined.mass_of_conflict();
    let missing = combined.mass_of_missing();

    // Update claim's DS columns
    MassFunctionRepository::update_claim_belief(
        &server.pool,
        claim_id,
        bel,
        pl,
        conflict,
        Some(betp),
        missing,
    )
    .await
    .map_err(internal_error)?;

    success_json(&DsEvidenceResponse {
        mass_function_id: mf_id.to_string(),
        claim_id: claim_id.to_string(),
        frame_id: frame_id.to_string(),
        belief: bel,
        plausibility: pl,
        ignorance: ign,
        pignistic_prob: betp,
        mass_on_conflict: conflict,
        mass_on_missing: missing,
        bba_count: all_bbas.len() as i64,
        method_used: method_name,
    })
}

pub async fn get_belief(
    server: &EpiGraphMcpFull,
    params: GetBeliefParams,
) -> Result<CallToolResult, McpError> {
    let claim_id = parse_uuid(&params.claim_id)?;
    let frame_id = params.frame_id.as_deref().map(parse_uuid).transpose()?;

    let interval = epigraph_engine::belief_query::get_belief(&server.pool, claim_id, frame_id)
        .await
        .map_err(|e| match e {
            epigraph_engine::BeliefQueryError::FrameNotFound(id) => {
                invalid_params(format!("frame {id} not found"))
            }
            epigraph_engine::BeliefQueryError::ClaimNotFound(id) => {
                invalid_params(format!("claim {id} not found"))
            }
            epigraph_engine::BeliefQueryError::ParseMasses(msg) => {
                invalid_params(format!("invalid mass function: {msg}"))
            }
            other => internal_error(other),
        })?;

    let ignorance = interval.plausibility - interval.belief;
    success_json(&BeliefResponse {
        claim_id: claim_id.to_string(),
        belief: interval.belief,
        plausibility: interval.plausibility,
        ignorance,
        pignistic_prob: interval.pignistic_prob,
        mass_on_conflict: interval.mass_on_conflict,
        mass_on_missing: interval.mass_on_missing,
        source: interval.source,
    })
}

pub async fn list_frames(
    server: &EpiGraphMcpFull,
    params: ListFramesParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let frames = FrameRepository::list(&server.pool, limit, 0)
        .await
        .map_err(internal_error)?;

    let entries: Vec<FrameEntry> = frames
        .into_iter()
        .map(|f| FrameEntry {
            frame_id: f.id.to_string(),
            name: f.name,
            description: f.description,
            hypotheses: f.hypotheses,
            version: f.version,
            parent_frame_id: f.parent_frame_id.map(|p| p.to_string()),
            is_refinable: f.is_refinable,
        })
        .collect();

    success_json(&entries)
}

pub async fn compare_methods(
    server: &EpiGraphMcpFull,
    params: CompareMethodsParams,
) -> Result<CallToolResult, McpError> {
    let claim_id = parse_uuid(&params.claim_id)?;
    let frame_id = parse_uuid(&params.frame_id)?;

    let frame_row = FrameRepository::get_by_id(&server.pool, frame_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("frame {frame_id} not found")))?;

    let frame = FrameOfDiscernment::new(frame_row.name.clone(), frame_row.hypotheses.clone())
        .map_err(internal_error)?;

    let all_bbas = MassFunctionRepository::get_for_claim_frame(&server.pool, claim_id, frame_id)
        .await
        .map_err(internal_error)?;

    if all_bbas.is_empty() {
        return Err(invalid_params("no BBAs stored for this claim/frame"));
    }

    let mut mass_fns = Vec::new();
    for row in &all_bbas {
        mass_fns.push(parse_masses_json(&frame, &row.masses)?);
    }

    let hypothesis_index = params.hypothesis_index as usize;
    let target = FocalElement::positive(BTreeSet::from([hypothesis_index]));

    let methods = [
        CombinationMethod::Conjunctive,
        CombinationMethod::Dempster,
        CombinationMethod::YagerOpen,
        CombinationMethod::YagerClosed,
        CombinationMethod::DuboisPrade,
        CombinationMethod::Inagaki,
    ];

    let mut results = Vec::new();
    for method in methods {
        if mass_fns.len() == 1 {
            let mf = &mass_fns[0];
            let bel = epigraph_ds::measures::belief(mf, &target);
            let pl = epigraph_ds::measures::plausibility(mf, &target);
            let betp = epigraph_ds::measures::pignistic_probability(mf, hypothesis_index);
            results.push(CompareMethodResult {
                method: format!("{method:?}"),
                belief: bel,
                plausibility: pl,
                pignistic_prob: betp,
                mass_on_conflict: mf.mass_of_conflict(),
                mass_on_missing: mf.mass_of_missing(),
            });
        } else {
            match (|| -> Result<_, McpError> {
                let mut result = mass_fns[0].clone();
                for mf in &mass_fns[1..] {
                    result = combine_two(&result, mf, method, None)?;
                }
                let bel = epigraph_ds::measures::belief(&result, &target);
                let pl = epigraph_ds::measures::plausibility(&result, &target);
                let betp = epigraph_ds::measures::pignistic_probability(&result, hypothesis_index);
                Ok(CompareMethodResult {
                    method: format!("{method:?}"),
                    belief: bel,
                    plausibility: pl,
                    pignistic_prob: betp,
                    mass_on_conflict: result.mass_of_conflict(),
                    mass_on_missing: result.mass_of_missing(),
                })
            })() {
                Ok(r) => results.push(r),
                Err(_) => {
                    results.push(CompareMethodResult {
                        method: format!("{method:?}"),
                        belief: 0.0,
                        plausibility: 0.0,
                        pignistic_prob: 0.0,
                        mass_on_conflict: 0.0,
                        mass_on_missing: 0.0,
                    });
                }
            }
        }
    }

    success_json(&CompareMethodsResponse {
        claim_id: claim_id.to_string(),
        frame_id: frame_id.to_string(),
        hypothesis_index: params.hypothesis_index,
        results,
    })
}

pub async fn scoped_belief(
    server: &EpiGraphMcpFull,
    params: ScopedBeliefParams,
) -> Result<CallToolResult, McpError> {
    let claim_id = parse_uuid(&params.claim_id)?;
    let scope_id = parse_uuid(&params.scope_id)?;

    let scope_type = match params.scope_type.to_lowercase().as_str() {
        "perspective" => "perspective",
        "community" => "community",
        other => {
            return Err(invalid_params(format!(
                "scope_type must be 'perspective' or 'community', got '{other}'"
            )));
        }
    };

    let row = ScopedBeliefRepository::get(&server.pool, claim_id, scope_type, Some(scope_id))
        .await
        .map_err(internal_error)?
        .ok_or_else(|| {
            invalid_params(format!(
                "no scoped belief for claim {claim_id} with {scope_type} {scope_id}"
            ))
        })?;

    success_json(&ScopedBeliefResponse {
        claim_id: claim_id.to_string(),
        scope_type: scope_type.to_string(),
        scope_id: scope_id.to_string(),
        belief: row.belief,
        plausibility: row.plausibility,
        mass_on_conflict: row.mass_on_empty,
        mass_on_missing: row.mass_on_missing,
        pignistic_prob: row.pignistic_prob,
    })
}

pub async fn get_divergence(
    server: &EpiGraphMcpFull,
    params: GetDivergenceParams,
) -> Result<CallToolResult, McpError> {
    let claim_id = parse_uuid(&params.claim_id)?;

    let row = DivergenceRepository::get_latest(&server.pool, claim_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("no divergence data for claim {claim_id}")))?;

    success_json(&DivergenceResponse {
        claim_id: claim_id.to_string(),
        pignistic_prob: row.pignistic_prob,
        bayesian_posterior: row.bayesian_posterior,
        kl_divergence: row.kl_divergence,
        computed_at: row.computed_at.to_rfc3339(),
    })
}

/// Convert a FocalElement to a string key for JSON serialization.
fn focal_to_key(fe: &FocalElement) -> String {
    if fe.is_conflict() {
        return String::new();
    }
    let indices: Vec<String> = fe
        .subset
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    if fe.complement {
        format!("~{}", indices.join(","))
    } else {
        indices.join(",")
    }
}
