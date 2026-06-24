//! CI drift guard: the DuckDB `flow` view SELECT, the Arrow schema, and
//! `flow_columns_in_order()` must all agree on column names and order.

use ppcap_core::columnar::schema::{flow_arrow_schema, flow_columns_in_order};

/// The shipped DDL embedded at compile time (same file the CLI emits).
const SCHEMA_SQL: &str = include_str!("../sql/schema.sql");

#[test]
fn arrow_schema_matches_canonical_order() {
    let schema = flow_arrow_schema();
    let names: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
    let canonical = flow_columns_in_order();
    assert_eq!(names.len(), 29);
    assert_eq!(names.as_slice(), &canonical[..], "Arrow field order drift");
}

#[test]
fn sql_view_select_matches_canonical_order() {
    // Locate the `CREATE VIEW flow AS SELECT ... FROM` block.
    let upper = SCHEMA_SQL.to_ascii_uppercase();
    let view_pos = upper
        .find("CREATE VIEW FLOW AS")
        .expect("flow view definition present");
    let after_view = &SCHEMA_SQL[view_pos..];
    let upper_after = &upper[view_pos..];

    let select_pos = upper_after.find("SELECT").expect("SELECT in flow view");
    let from_pos = upper_after.find("FROM").expect("FROM in flow view");
    assert!(from_pos > select_pos, "FROM must follow SELECT");

    let select_list = &after_view[select_pos + "SELECT".len()..from_pos];

    let parsed: Vec<String> = select_list
        .split(',')
        .map(|tok| {
            // Strip comments, whitespace, and any trailing "AS alias".
            let tok = tok.split("--").next().unwrap_or(tok);
            let tok = tok.trim();
            // Take the column name (handle "expr AS alias" by keeping the leaf token).
            let last = tok.split_whitespace().last().unwrap_or(tok);
            last.trim().to_string()
        })
        .filter(|s| !s.is_empty())
        .collect();

    let canonical: Vec<String> = flow_columns_in_order()
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        parsed, canonical,
        "DuckDB flow VIEW SELECT list drifted from flow_columns_in_order()"
    );
}
