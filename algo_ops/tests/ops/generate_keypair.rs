use algo_ops::AlgoOps;

#[test]
fn generate_keypair_produces_valid_address_and_passphrase() {
    // Generate a new keypair
    let (id, passphrase) = AlgoOps::generate_keypair();

    // Basic sanity checks
    assert!(!id.is_empty(), "id must not be empty");
    assert_eq!(
        passphrase.split_whitespace().count(),
        25,
        "passphrase must be 25 words"
    );

    // Derive address again from passphrase and ensure it matches
    let ops = AlgoOps::new(Some(passphrase.clone()), None, None);
    let derived = ops
        .address
        .as_ref()
        .expect("AlgoOps should derive address from passphrase");
    assert_eq!(derived, &id, "derived address must equal generated id");

    // Round-trip sign/verify to ensure secret is usable
    let sig = ops.sign("hello world").expect("should sign");
    let ok = ops
        .verify("hello world", &sig)
        .expect("should verify computation");
    assert!(ok, "signature must verify");
}
