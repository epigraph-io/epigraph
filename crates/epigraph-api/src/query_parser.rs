use nom::{
    branch::alt,
    bytes::complete::{tag, tag_no_case, take_while1},
    character::complete::{char, digit1, multispace0},
    combinator::{map, map_res, opt, recognize},
    sequence::{delimited, preceded},
    IResult, Parser,
};
use serde::{Deserialize, Serialize};

/// Abstract Syntax Tree for our GQL / Cypher subset
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GqlQuery {
    pub match_clause: MatchClause,
    pub where_clause: Option<WhereClause>,
    pub limit: Option<usize>,
    pub return_clause: ReturnClause,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchClause {
    pub source_node: NodePattern,
    pub edge: Option<EdgePattern>,
    pub target_node: Option<NodePattern>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodePattern {
    pub variable: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EdgePattern {
    pub variable: Option<String>,
    pub rel_type: Option<String>,
    pub min_hops: usize,
    pub max_hops: usize,
    pub direction: EdgeDirection,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EdgeDirection {
    Outgoing, // -[]->
    Incoming, // <-[]-
    Any,      // -[]-
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WhereClause {
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Condition {
    pub variable: String,
    pub property: String,
    pub operator: Operator,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Operator {
    Eq,  // =
    Gt,  // >
    Lt,  // <
    Gte, // >=
    Lte, // <=
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    Number(f64),
    String(String),
    Boolean(bool),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ReturnClause {
    All,                    // RETURN *
    Variables(Vec<String>), // RETURN n, e, m
}

// --- PARSER UTILS ---

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn parse_variable(i: &str) -> IResult<&str, String> {
    map(take_while1(is_ident_char), String::from).parse(i)
}

fn ws<'a, F, O>(inner: F) -> impl Parser<&'a str, Output = O, Error = nom::error::Error<&'a str>>
where
    F: Parser<&'a str, Output = O, Error = nom::error::Error<&'a str>>,
{
    delimited(multispace0, inner, multispace0)
}

// --- PARSER ---

/// Parse `(n)` or `(n:claim)`
fn parse_node_pattern(i: &str) -> IResult<&str, NodePattern> {
    let (i, _) = char('(')(i)?;
    let (i, _) = multispace0(i)?;

    // Node always needs a variable in our subset for linking WHERE conditions
    let (i, variable) = parse_variable(i)?;
    let (i, _) = multispace0(i)?;

    let (i, label) = opt(preceded(char(':'), parse_variable)).parse(i)?;
    let (i, _) = multispace0(i)?;
    let (i, _) = char(')')(i)?;

    Ok((i, NodePattern { variable, label }))
}

/// Parse ranges like `*1..3` or `*..3` or `*2..` or just `*` (1..inf)
fn parse_variable_length(i: &str) -> IResult<&str, (usize, usize)> {
    let (i, _) = char('*')(i)?;

    // Parse optional min
    let (i, min_val) = opt(map_res(digit1, |s: &str| s.parse::<usize>())).parse(i)?;

    // Check for `..`
    let (i, has_dots) = opt(tag("..")).parse(i)?;

    if has_dots.is_some() {
        // Parse optional max
        let (i, max_val) = opt(map_res(digit1, |s: &str| s.parse::<usize>())).parse(i)?;
        let min = min_val.unwrap_or(0); // *..3 implies min 0
        let max = max_val.unwrap_or(10); // Cap at 10 hops for safety if infinite
        Ok((i, (min, max)))
    } else {
        // Just `*` -> 1..10 or `*2` -> exactly 2
        let val = min_val.unwrap_or(1); // Standard `*` is min 1
        let max = if min_val.is_none() { 10 } else { val };
        Ok((i, (val, max)))
    }
}

/// Parse `-[r:supports*1..3]->` or `-[*]->`
fn parse_edge_pattern(i: &str) -> IResult<&str, EdgePattern> {
    let (i, is_incoming) = opt(char('<')).parse(i)?;
    let (i, _) = tag("-")(i)?;

    // Check for embedded `[...]`
    let (i, inner) = opt(delimited(char('['), take_while1(|c| c != ']'), char(']'))).parse(i)?;

    let (i, _) = tag("-")(i)?;
    let (i, is_outgoing) = opt(char('>')).parse(i)?;

    let direction = match (is_incoming.is_some(), is_outgoing.is_some()) {
        (true, false) => EdgeDirection::Incoming,
        (false, true) => EdgeDirection::Outgoing,
        _ => EdgeDirection::Any,
    };

    let mut variable = None;
    let mut rel_type = None;
    let mut min_hops = 1;
    let mut max_hops = 1;

    // Parse inner `[r:supports*1..3]`
    if let Some(inner_str) = inner {
        // This is a naive split strategy for MVP
        let mut rest = inner_str;

        // Is there a variable before `:` or `*`?
        if let Ok((rem, var)) = parse_variable(rest) {
            variable = Some(var);
            rest = rem;
        }

        // Is there a type?
        if rest.starts_with(':') {
            rest = &rest[1..];
            let type_chars = rest.chars().take_while(|&c| c != '*').collect::<String>();
            if !type_chars.is_empty() {
                rel_type = Some(type_chars.clone());
                rest = &rest[type_chars.len()..];
            }
        }

        // Is there a hops specifier?
        if rest.starts_with('*') {
            if let Ok((_, (min, max))) = parse_variable_length(rest) {
                min_hops = min;
                max_hops = max;
            }
        }
    }

    Ok((
        i,
        EdgePattern {
            variable,
            rel_type,
            min_hops,
            max_hops,
            direction,
        },
    ))
}

fn parse_match_clause(i: &str) -> IResult<&str, MatchClause> {
    let (i, _) = ws(tag_no_case("MATCH")).parse(i)?;
    let (i, source_node) = ws(parse_node_pattern).parse(i)?;

    // Optional edge and target
    let (i, edge_tup) = opt((ws(parse_edge_pattern), ws(parse_node_pattern))).parse(i)?;

    let (edge, target_node) = match edge_tup {
        Some((e, t)) => (Some(e), Some(t)),
        None => (None, None),
    };

    Ok((
        i,
        MatchClause {
            source_node,
            edge,
            target_node,
        },
    ))
}

fn parse_value(i: &str) -> IResult<&str, Value> {
    alt((
        map(tag_no_case("true"), |_| Value::Boolean(true)),
        map(tag_no_case("false"), |_| Value::Boolean(false)),
        map(
            delimited(char('"'), take_while1(|c| c != '"'), char('"')),
            |s: &str| Value::String(s.to_string()),
        ),
        map(
            delimited(char('\''), take_while1(|c| c != '\''), char('\'')),
            |s: &str| Value::String(s.to_string()),
        ),
        map(
            map_res(
                recognize((opt(char('-')), digit1, opt((char('.'), digit1)))),
                |s: &str| s.parse::<f64>(),
            ),
            Value::Number,
        ),
    ))
    .parse(i)
}

fn parse_operator(i: &str) -> IResult<&str, Operator> {
    alt((
        map(tag(">="), |_| Operator::Gte),
        map(tag("<="), |_| Operator::Lte),
        map(tag("="), |_| Operator::Eq),
        map(tag(">"), |_| Operator::Gt),
        map(tag("<"), |_| Operator::Lt),
    ))
    .parse(i)
}

fn parse_condition(i: &str) -> IResult<&str, Condition> {
    let (i, variable) = ws(parse_variable).parse(i)?;
    let (i, _) = char('.')(i)?;
    let (i, property) = ws(parse_variable).parse(i)?;
    let (i, operator) = ws(parse_operator).parse(i)?;
    let (i, value) = ws(parse_value).parse(i)?;

    Ok((
        i,
        Condition {
            variable,
            property,
            operator,
            value,
        },
    ))
}

fn parse_where_clause(i: &str) -> IResult<&str, WhereClause> {
    let (i, _) = ws(tag_no_case("WHERE")).parse(i)?;

    // Currently only supporting a single AND chain
    // Real cypher supports OR, parens, etc. but MVP supports just basic AND
    // For MVP, just pull the first condition.  Adding " AND " looping requires many1.
    // Simplifying to a single condition for v0 parser.
    let (i, cond) = ws(parse_condition).parse(i)?;

    Ok((
        i,
        WhereClause {
            conditions: vec![cond],
        },
    ))
}

fn parse_return_clause(i: &str) -> IResult<&str, ReturnClause> {
    let (i, _) = ws(tag_no_case("RETURN")).parse(i)?;

    let (i, all) = opt(ws(char('*'))).parse(i)?;
    if all.is_some() {
        return Ok((i, ReturnClause::All));
    }

    // Parse comma-separated variable list, stopping before LIMIT or end of input
    let mut vars = Vec::new();
    let mut remaining = i;
    loop {
        let trimmed = remaining.trim_start();
        // Stop if we hit LIMIT or end of input
        if trimmed.is_empty() || trimmed.to_uppercase().starts_with("LIMIT") {
            remaining = trimmed;
            break;
        }
        // Parse one identifier
        let end = trimmed
            .find(|c: char| !c.is_alphanumeric() && c != '_')
            .unwrap_or(trimmed.len());
        if end == 0 {
            break;
        }
        vars.push(trimmed[..end].to_string());
        remaining = trimmed[end..].trim_start();
        // Consume optional comma
        if remaining.starts_with(',') {
            remaining = &remaining[1..];
        }
    }
    let i = remaining;
    if vars.is_empty() {
        return Err(nom::Err::Error(nom::error::Error::new(
            i,
            nom::error::ErrorKind::Alpha,
        )));
    }

    Ok((i, ReturnClause::Variables(vars)))
}

fn parse_limit(i: &str) -> IResult<&str, usize> {
    let (i, _) = ws(tag_no_case("LIMIT")).parse(i)?;
    let (i, size) = map_res(ws(digit1), |s: &str| s.parse::<usize>()).parse(i)?;
    Ok((i, size))
}

pub fn parse_gql(query: &str) -> Result<GqlQuery, String> {
    let query = query.trim();

    // Parse match clause
    let (i, match_clause) = match parse_match_clause(query) {
        Ok(res) => res,
        Err(e) => return Err(format!("Match parse error: {:?}", e)),
    };

    // Parse optional where clause
    let (i, where_clause) = match opt(parse_where_clause).parse(i) {
        Ok(res) => res,
        Err(e) => return Err(format!("Where parse error: {:?}", e)),
    };

    // Parse return clause
    let (i, return_clause) = match parse_return_clause(i) {
        Ok(res) => res,
        Err(e) => return Err(format!("Return parse error: {:?}", e)),
    };

    // Parse optional limit
    let (i, limit) = match opt(parse_limit).parse(i) {
        Ok(res) => res,
        Err(e) => return Err(format!("Limit parse error: {:?}", e)),
    };

    if !i.trim().is_empty() {
        return Err(format!("Trailing characters left after parsing: {}", i));
    }

    Ok(GqlQuery {
        match_clause,
        where_clause,
        limit,
        return_clause,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_only() {
        let q = "MATCH (n:claim) RETURN *";
        let res = parse_gql(q).unwrap();
        assert_eq!(res.match_clause.source_node.variable, "n");
        assert_eq!(
            res.match_clause.source_node.label,
            Some("claim".to_string())
        );
        assert_eq!(res.return_clause, ReturnClause::All);
    }

    #[test]
    fn test_edge_and_where() {
        let q = "MATCH (c:claim)-[r:supports*1..3]->(e:evidence) WHERE c.truth_value = 1.0 RETURN c, e LIMIT 50";
        let res = parse_gql(q).unwrap();

        let edge = res.match_clause.edge.unwrap();
        assert_eq!(edge.direction, EdgeDirection::Outgoing);
        assert_eq!(edge.min_hops, 1);
        assert_eq!(edge.max_hops, 3);
        assert_eq!(edge.rel_type, Some("supports".to_string()));

        let wc = res.where_clause.unwrap();
        assert_eq!(wc.conditions[0].variable, "c");
        assert_eq!(wc.conditions[0].property, "truth_value");
        assert_eq!(wc.conditions[0].value, Value::Number(1.0));

        assert_eq!(res.limit, Some(50));
    }
}
