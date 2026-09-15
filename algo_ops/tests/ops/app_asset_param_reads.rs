//! Unit tests for the pure JSON parsers behind `AlgoOps::app_creator` / `AlgoOps::asset_clawback`,
//! used by the `--new-app` migration precheck. No node — they parse an algod info value.

use algo_ops::AlgoOps;
use serde_json::json;

#[test]
fn app_creator_from_params() {
    let v = json!({ "id": 42, "params": { "creator": "CREATORADDR" } });
    assert_eq!(
        AlgoOps::parse_app_creator_from_app_info_value(&v),
        Some("CREATORADDR".to_string())
    );
}

#[test]
fn app_creator_top_level_fallback_and_missing() {
    // Some serializations put creator at the top level.
    let top = json!({ "id": 1, "creator": "TOPADDR", "params": {} });
    assert_eq!(
        AlgoOps::parse_app_creator_from_app_info_value(&top),
        Some("TOPADDR".to_string())
    );
    // Absent creator -> None.
    let none = json!({ "id": 1, "params": {} });
    assert_eq!(AlgoOps::parse_app_creator_from_app_info_value(&none), None);
}

#[test]
fn asset_clawback_present() {
    let v = json!({ "index": 7, "params": { "clawback": "CLAWBACKADDR" } });
    assert_eq!(
        AlgoOps::parse_clawback_from_asset_info_value(&v),
        Some("CLAWBACKADDR".to_string())
    );
    // Hyphenated key variant.
    let hy = json!({ "index": 7, "params": { "clawback-address": "CLAWADDR2" } });
    assert_eq!(
        AlgoOps::parse_clawback_from_asset_info_value(&hy),
        Some("CLAWADDR2".to_string())
    );
}

#[test]
fn asset_clawback_absent_or_empty_is_none() {
    // algod omits an unset clawback.
    let absent = json!({ "index": 7, "params": { "creator": "X" } });
    assert_eq!(AlgoOps::parse_clawback_from_asset_info_value(&absent), None);
    // Empty string also counts as unset.
    let empty = json!({ "index": 7, "params": { "clawback": "" } });
    assert_eq!(AlgoOps::parse_clawback_from_asset_info_value(&empty), None);
}
