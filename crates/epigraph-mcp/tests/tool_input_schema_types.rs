//! Every free-form JSON parameter must declare a concrete JSON Schema `type`.
//!
//! Backlog BL-1: `submit_ds_evidence`'s `masses` parameter had no declared
//! `type` in the generated `inputSchema`. schemars 1 renders a bare
//! `serde_json::Value` field as the *permissive* schema (the JSON literal
//! `true`, which a `description` attribute then widens to a lone
//! `{"description": "..."}` object) — no type information at all. Clients that
//! build their argument payload from the advertised schema have nothing to tell
//! them the value is an object, serialise it as a string, and the server
//! rejects the call before any work happens. The tool is effectively
//! uncallable.
//!
//! This test asserts against `EpiGraphMcpFull::all_tools_json()` — the same
//! router-derived schema that `tools/list` hands the client — rather than
//! re-deriving with `schema_for!`, so it fails if the wire contract regresses
//! even when the type definitions still look right.

use epigraph_mcp::EpiGraphMcpFull;

/// A tool's whole `inputSchema`, needed because a `$ref` resolves against the
/// `$defs` that sits beside `properties`.
fn input_schema(tools: &serde_json::Value, tool: &str) -> serde_json::Value {
    tools
        .as_array()
        .expect("all_tools_json must return an array")
        .iter()
        .find(|t| t.get("name").and_then(serde_json::Value::as_str) == Some(tool))
        .unwrap_or_else(|| panic!("tool `{tool}` is not registered on the router"))
        .get("inputSchema")
        .unwrap_or_else(|| panic!("tool `{tool}` has no inputSchema"))
        .clone()
}

/// Locate a tool's declared subschema for one named parameter.
fn property_schema(tools: &serde_json::Value, tool: &str, field: &str) -> serde_json::Value {
    let schema = input_schema(tools, tool);
    schema
        .get("properties")
        .and_then(|p| p.get(field))
        .unwrap_or_else(|| {
            panic!("tool `{tool}` declares no `{field}` property; inputSchema = {schema}")
        })
        .clone()
}

/// Follow one level of indirection to the subschema that actually carries the
/// type.
///
/// A named `JsonSchema` struct behind an `Option` renders as
/// `{"anyOf": [{"$ref": "#/$defs/T"}, {"const": null}]}` — the `$ref` target
/// in `$defs` holds `"type": "object"` plus every property. That is STRONGER
/// type information than an inline `"type": "object"`, so it must satisfy the
/// same assertion; but an unresolvable `$ref`, or a branch with no type at
/// all, still fails, which is the BL-1 regression being guarded.
fn resolve<'a>(
    input_schema: &'a serde_json::Value,
    schema: &'a serde_json::Value,
) -> serde_json::Value {
    let Some(branches) = schema.get("anyOf").and_then(serde_json::Value::as_array) else {
        return schema.clone();
    };
    // Skip the null branch schemars emits for the `Option` wrapper.
    let non_null = branches
        .iter()
        .find(|b| b.get("const") != Some(&serde_json::Value::Null))
        .unwrap_or_else(|| panic!("anyOf has only a null branch: {schema}"));

    let Some(reference) = non_null.get("$ref").and_then(serde_json::Value::as_str) else {
        return non_null.clone();
    };
    let name = reference.strip_prefix("#/$defs/").unwrap_or_else(|| {
        panic!("only local $defs references are resolvable here; got {reference}")
    });
    input_schema
        .get("$defs")
        .and_then(|d| d.get(name))
        .unwrap_or_else(|| panic!("dangling $ref {reference}: no $defs/{name} in {input_schema}"))
        .clone()
}

/// True when `schema` declares `type` equal to `expected`, either directly
/// (`"type": "object"`) or as one member of a union (`"type": ["object",
/// "null"]`, which is how schemars renders an `Option<T>`).
fn declares_type(schema: &serde_json::Value, expected: &str) -> bool {
    match schema.get("type") {
        Some(serde_json::Value::String(s)) => s == expected,
        Some(serde_json::Value::Array(v)) => v.iter().any(|t| t.as_str() == Some(expected)),
        _ => false,
    }
}

/// True when the property may be omitted or sent as null: `nullable: true`, a
/// `"null"` type member, or an `anyOf` branch that is the null constant.
fn admits_null(schema: &serde_json::Value) -> bool {
    if schema.get("nullable") == Some(&serde_json::Value::Bool(true))
        || declares_type(schema, "null")
    {
        return true;
    }
    schema
        .get("anyOf")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|branches| {
            branches.iter().any(|b| {
                b.get("const") == Some(&serde_json::Value::Null)
                    || b.get("nullable") == Some(&serde_json::Value::Bool(true))
                    || declares_type(b, "null")
            })
        })
}

fn assert_declares(tools: &serde_json::Value, tool: &str, field: &str, expected: &str) {
    let declared = property_schema(tools, tool, field);
    let schema = resolve(&input_schema(tools, tool), &declared);

    // The regression being guarded is a schema of the JSON literal `true` (or
    // `{}`): syntactically valid, semantically "anything goes", and useless to
    // a client that has to decide how to serialise the argument.
    assert!(
        schema.is_object(),
        "`{tool}.{field}` schema is the permissive literal `{schema}`, not an object — \
         a client has no way to know it must send a JSON {expected}"
    );
    assert!(
        declares_type(&schema, expected),
        "`{tool}.{field}` must declare \"type\": \"{expected}\" (bare or in a union with \
         \"null\"); got {schema}"
    );
    // Pinning the type must not cost the prose that tells an agent what to put
    // in the field — schemars merges `with` and `description`, and a future
    // bump that stops merging them would silently strip every one of these.
    // Read it off the DECLARED property: that is where a client looking at
    // `properties.<field>` finds it, whether or not the type sits behind a
    // `$ref`.
    assert!(
        declared
            .get("description")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|d| !d.is_empty()),
        "`{tool}.{field}` lost its description when the type was pinned; got {declared}"
    );
    println!("{tool}.{field} => {schema}");
}

#[test]
fn free_form_json_params_declare_a_concrete_type() {
    let tools = EpiGraphMcpFull::all_tools_json();

    // Required (non-Option) object parameters.
    assert_declares(&tools, "submit_ds_evidence", "masses", "object");
    assert_declares(&tools, "publish_event", "payload", "object");

    // Optional object parameters — the `Option` wrapper must survive, so these
    // are additionally allowed (and expected) to admit "null".
    assert_declares(&tools, "link_hierarchical", "properties", "object");
    assert_declares(&tools, "link_epistemic", "properties", "object");
    assert_declares(&tools, "patch_claim", "properties", "object");
    // Backlog 4b48ffb5: the coverage contract override. A bare
    // `serde_json::Value` here would leave a client unable to tell that
    // `{"standard": "summary"}` is an object, re-introducing BL-1 on the one
    // tool whose default contract most callers will want to relabel.
    assert_declares(&tools, "batch_submit_claims", "coverage", "object");
}

/// The three optional parameters must stay optional. Declaring a type is only
/// a fix if it does not silently promote the field to required — that would
/// break every existing caller that omits it.
#[test]
fn optional_object_params_stay_optional() {
    let tools = EpiGraphMcpFull::all_tools_json();

    for (tool, field) in [
        ("link_hierarchical", "properties"),
        ("link_epistemic", "properties"),
        ("patch_claim", "properties"),
        ("batch_submit_claims", "coverage"),
    ] {
        let entry = tools
            .as_array()
            .expect("array")
            .iter()
            .find(|t| t.get("name").and_then(serde_json::Value::as_str) == Some(tool))
            .unwrap_or_else(|| panic!("tool `{tool}` is not registered"));

        let required = entry
            .get("inputSchema")
            .and_then(|s| s.get("required"))
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();

        assert!(
            !required.iter().any(|r| r.as_str() == Some(field)),
            "`{tool}.{field}` is Option<_> and must not appear in `required`; required = {required:?}"
        );

        // Absent from `required` is only half of "optional": the value must
        // also still be allowed to *be* null. rmcp renders that as
        // `"nullable": true` for an inline type and as an `anyOf` null branch
        // for a `$ref`'d one; a schemars/rmcp bump could switch to the
        // `"type": ["object","null"]` union instead. Any of the three is fine
        // — silently losing all of them is not, and `required` alone would not
        // catch it.
        let schema = property_schema(&tools, tool, field);
        assert!(
            admits_null(&schema),
            "`{tool}.{field}` is Option<_> but its schema no longer admits null \
             (no `nullable: true`, no \"null\" type member, no null anyOf branch); got {schema}"
        );
    }
}

/// `masses` values must be advertised as plain numbers. Typing them as `f64`
/// would also emit `"format": "double"`, and a certain mass of 1.0 arrives as
/// the JSON integer `1` from any client whose encoder drops the trailing
/// `.0` — which the handler accepts (serde coerces int to f64) but a
/// format-asserting client validator could reject. That would re-introduce a
/// narrower copy of the very "tool is uncallable" bug BL-1 describes.
#[test]
fn ds_mass_values_are_plain_numbers_not_format_constrained() {
    let tools = EpiGraphMcpFull::all_tools_json();
    let schema = property_schema(&tools, "submit_ds_evidence", "masses");

    let values = schema
        .get("additionalProperties")
        .unwrap_or_else(|| panic!("masses must constrain its values; got {schema}"));

    assert!(
        declares_type(values, "number"),
        "masses values must declare \"type\": \"number\"; got {values}"
    );
    assert!(
        values.get("format").is_none(),
        "masses values must not carry a `format` assertion — the integer `1` is a \
         legal certain mass and the handler accepts it; got {values}"
    );
}
