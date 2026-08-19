// Unit-style tests for the JSON parsing helpers used by recover_reserve_balance.
//
// `parse_creator_reserve_from_asset_info_value` and
// `parse_holding_amount_from_account_value` are `pub` because they are used in
// production paths (`asset_holding` / `recover_reserve_balance`); these tests
// exercise the parsing directly.

use algo_ops::AlgoOps;
use serde_json::json;

#[test]
#[cfg(not(target_os = "ios"))]
pub fn test_parse_creator_reserve_from_asset_info_value_variants() {
    // Variant A: fields under params with standard keys
    let v1 = json!({
        "params": {
            "creator": "CREATORADDR",
            "reserve": "RESERVEADDR"
        }
    });
    let t1 = AlgoOps::parse_creator_reserve_from_asset_info_value(&v1);
    assert!(t1.is_some());
    let (c1, r1) = t1.unwrap();
    assert_eq!(c1, "CREATORADDR");
    assert_eq!(r1, "RESERVEADDR");

    // Variant B: creator at top-level, reserve under params with dashed key
    let v2 = json!({
        "creator": "TOPLEVELCREATOR",
        "params": { "reserve-address": "DASHEDRESERVE" }
    });
    let t2 = AlgoOps::parse_creator_reserve_from_asset_info_value(&v2);
    assert!(t2.is_some());
    let (c2, r2) = t2.unwrap();
    assert_eq!(c2, "TOPLEVELCREATOR");
    assert_eq!(r2, "DASHEDRESERVE");

    // Variant C: underscored reserve key
    let v3 = json!({
        "params": { "creator": "C3", "reserve_address": "R3" }
    });
    let t3 = AlgoOps::parse_creator_reserve_from_asset_info_value(&v3);
    assert!(t3.is_some());
    let (c3, r3) = t3.unwrap();
    assert_eq!(c3, "C3");
    assert_eq!(r3, "R3");
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn test_parse_holding_amount_from_account_value() {
    let v = json!({
        "assets": [
            {"asset-id": 111, "amount": 5},
            {"asset_id": 222, "amount": 0},
            {"asset-id": 333, "amount": 42}
        ]
    });
    assert_eq!(AlgoOps::parse_holding_amount_from_account_value(&v, 111), 5);
    assert_eq!(AlgoOps::parse_holding_amount_from_account_value(&v, 222), 0);
    assert_eq!(
        AlgoOps::parse_holding_amount_from_account_value(&v, 333),
        42
    );
    assert_eq!(AlgoOps::parse_holding_amount_from_account_value(&v, 444), 0);
}
