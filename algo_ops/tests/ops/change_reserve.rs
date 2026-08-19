use algo_ops::AlgoOps;

// These are unit-style tests that validate parameter checking without hitting the network.
// They do not require a running node.

#[test]
#[cfg(not(target_os = "ios"))]
pub fn change_reserve_errors_on_zero_asset_id() {
    let ops = AlgoOps::new(
        None,
        Some("P577PSTDICQ6PQFBR5YMDMJ2YVK7LT5V4GOPNVDLCEDJIL7XGRWC5BRFWA".to_string()),
        None,
    );
    let err = ops
        .change_asset_reserve_address(
            0,
            "4TKGNGRAUHMQI4EOQ34L2AIDX2VGS4OZNZIOE6BLEQFZUDRSB6RJRBPVRE",
        )
        .unwrap_err();
    let msg = format!("{}", err);
    assert!(msg.contains("asset_id must be > 0"));
}

#[test]
#[cfg(not(target_os = "ios"))]
pub fn change_reserve_errors_on_invalid_reserve_address() {
    // No passphrase/address required for this error path; invalid reserve address is validated first
    let ops = AlgoOps::new(
        None,
        Some("P577PSTDICQ6PQFBR5YMDMJ2YVK7LT5V4GOPNVDLCEDJIL7XGRWC5BRFWA".to_string()),
        None,
    );
    let err = ops
        .change_asset_reserve_address(12345, "not-an-address")
        .unwrap_err();
    let msg = format!("{}", err);
    assert!(msg.contains("invalid reserve address"));
}
