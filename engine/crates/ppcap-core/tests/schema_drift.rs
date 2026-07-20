//! CI drift guard: the DuckDB `flow` view SELECT, the Arrow schema,
//! `flow_columns_in_order()`, and the UI's shared fixture
//! (ui/src/lib/query/flow_columns.json) must all agree on column names and order.

use ppcap_core::columnar::schema::{
    flow_arrow_schema, flow_columns_in_order, FLOW_PARQUET_VERSION,
};

/// The shipped DDL embedded at compile time (same file the CLI emits).
const SCHEMA_SQL: &str = include_str!("../sql/schema.sql");

#[test]
fn arrow_schema_matches_canonical_order() {
    let schema = flow_arrow_schema();
    let names: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
    let canonical = flow_columns_in_order();
    assert_eq!(names.len(), 31);
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

/// The UI builds its in-browser DuckDB `flow` table from this shared fixture's
/// column list (ui/src/lib/query/schema.ts guards its side with a vitest). A
/// schema change here must ship with an updated fixture, or CI fails on both ends.
#[test]
fn ui_fixture_matches_canonical_order() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../ui/src/lib/query/flow_columns.json"
    );
    let raw = std::fs::read_to_string(path)
        .expect("ui/src/lib/query/flow_columns.json present (shared drift fixture)");
    let fixture: serde_json::Value = serde_json::from_str(&raw).expect("fixture is valid JSON");

    assert_eq!(
        fixture["flow_schema_version"].as_u64(),
        Some(u64::from(FLOW_PARQUET_VERSION)),
        "fixture flow_schema_version drifted from FLOW_PARQUET_VERSION"
    );

    let columns: Vec<&str> = fixture["columns"]
        .as_array()
        .expect("fixture has a columns array")
        .iter()
        .map(|v| v.as_str().expect("column names are strings"))
        .collect();
    assert_eq!(
        columns.as_slice(),
        &flow_columns_in_order()[..],
        "UI flow_columns.json fixture drifted from flow_columns_in_order()"
    );
}
