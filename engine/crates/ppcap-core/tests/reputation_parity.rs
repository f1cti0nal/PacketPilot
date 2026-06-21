//! Asserts native apply_reputation matches the shared parity fixture (the WASM side asserts the
//! same `expected` in ui/src/lib/reputation/parity.test.ts → byte-identical scoring across surfaces).
use std::collections::BTreeMap;

#[test]
fn native_apply_matches_fixture() {
    let raw = include_str!("../../../../ui/src/test/reputation-parity.fixture.json");
    let fx: serde_json::Value = serde_json::from_str(raw).unwrap();
    let mut out: ppcap_core::AnalysisOutput = serde_json::from_value(fx["output"].clone()).unwrap();
    let verdicts: BTreeMap<String, Vec<ppcap_core::ReputationVerdict>> =
        serde_json::from_value(fx["verdicts"].clone()).unwrap();
    ppcap_core::apply_reputation(&mut out.summary, &verdicts);

    let expected = &fx["expected"]["ip_threats"];
    assert_eq!(
        out.summary.ip_threats.len(),
        expected.as_array().unwrap().len(),
        "ip_threats length mismatch"
    );
    for (i, row) in out.summary.ip_threats.iter().enumerate() {
        assert_eq!(
            row.severity.as_str(),
            expected[i]["severity"].as_str().unwrap(),
            "row {i} severity"
        );
        assert_eq!(
            row.score as u64,
            expected[i]["score"].as_u64().unwrap(),
            "row {i} score"
        );
        assert_eq!(
            row.ip,
            expected[i]["ip"].as_str().unwrap(),
            "row {i} ip/order"
        );
    }
}
