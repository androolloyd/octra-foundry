//! `slash_double_sign` happy + sad paths.
//!
//! Verifies the v1.1 cryptographic equivocation slash: two off-chain
//! receipt payloads signed by the same operator key under the
//! receipt_pubkey registered at `register_endpoint` time. The mock
//! chain's apply_slash_double_sign re-implements the AML semantics
//! including real ed25519 verification.

use ed25519_dalek::{Signer, SigningKey};
use octraforge::{octra_test, ForgeCtx};
use rand::rngs::OsRng;

const OWNER: &str = "octOWNER0slash000000000000000000000000001";
const OP: &str = "octOPslash000000000000000000000000000001";
const SLASHER: &str = "octSLASHER0000000000000000000000000000001";

fn register_op_with_receipt_pubkey(forge: &mut ForgeCtx) -> SigningKey {
    forge.become_octra_validator(OP);
    let sk = SigningKey::generate(&mut OsRng);
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
    forge.prank(OP);
    forge
        .call_register_endpoint(
            "1.2.3.4:51820",
            &"de".repeat(32),
            &"fe".repeat(32),
            &"00".repeat(32),
            "eu-west",
            100,
            &pk_hex,
        )
        .expect("register");
    sk
}

/// Build a signed receipt payload + sig pair. The AML
/// `ed25519_ok(pk, payload, sig)` verifies the sig over the payload
/// STRING bytes; this helper signs whatever string the caller will
/// pass to the AML so the test stays consistent with the mock.
fn signed(sk: &SigningKey, payload: &str) -> String {
    hex::encode(sk.sign(payload.as_bytes()).to_bytes())
}

octra_test!(slash_double_sign_happy_path, |forge| {
    forge.deploy_octravpn(100, 10);
    forge.set_program_owner(OWNER);
    let op_sk = register_op_with_receipt_pubkey(&mut forge);

    // Two distinct off-chain receipt payloads — the operator signed
    // two contradictory bytes_used values for the same session.
    let payload_a = "octravpn-receipt-v1|session=1|bytes=100|blind=aa";
    let payload_b = "octravpn-receipt-v1|session=1|bytes=200|blind=bb";
    let sig_a = signed(&op_sk, payload_a);
    let sig_b = signed(&op_sk, payload_b);

    forge.prank(SLASHER);
    let res = forge
        .call_slash_double_sign(OP, 1, payload_a, &sig_a, payload_b, &sig_b)
        .expect("slash should succeed");
    assert!(res.find_event("OperatorSlashed").is_some(), "slash event");
    assert_eq!(
        res.event_str("OperatorSlashed", "reason"),
        Some("double-sign".to_string())
    );
});

octra_test!(slash_double_sign_rejects_identical_payloads, |forge| {
    forge.deploy_octravpn(100, 10);
    forge.set_program_owner(OWNER);
    let op_sk = register_op_with_receipt_pubkey(&mut forge);

    let payload = "octravpn-receipt-v1|session=2|bytes=50|blind=aa";
    let sig = signed(&op_sk, payload);

    forge.prank(SLASHER);
    forge.expect_revert("payloads identical");
    let _ = forge.call_slash_double_sign(OP, 2, payload, &sig, payload, &sig);
});

octra_test!(slash_double_sign_rejects_bad_signature, |forge| {
    forge.deploy_octravpn(100, 10);
    forge.set_program_owner(OWNER);
    let _ = register_op_with_receipt_pubkey(&mut forge);

    let payload_a = "octravpn-receipt-v1|session=3|bytes=10|blind=aa";
    let payload_b = "octravpn-receipt-v1|session=3|bytes=20|blind=bb";
    // Sign with a different key — the receipt_pubkey gate should reject.
    let imposter = SigningKey::generate(&mut OsRng);
    let bad_sig_a = signed(&imposter, payload_a);
    let bad_sig_b = signed(&imposter, payload_b);

    forge.prank(SLASHER);
    forge.expect_revert("sig_a invalid");
    let _ = forge.call_slash_double_sign(OP, 3, payload_a, &bad_sig_a, payload_b, &bad_sig_b);
});

octra_test!(slash_double_sign_rejects_missing_receipt_pubkey, |forge| {
    forge.deploy_octravpn(100, 10);
    forge.set_program_owner(OWNER);
    forge.become_octra_validator(OP);
    // Register WITHOUT a receipt_pubkey (empty string).
    forge.prank(OP);
    forge
        .call_register_endpoint_simple("1.2.3.4:51820", &"de".repeat(32), "eu-west", 100)
        .expect("register");
    let payload_a = "octravpn-receipt-v1|session=4|bytes=1|blind=a";
    let payload_b = "octravpn-receipt-v1|session=4|bytes=2|blind=b";
    let sk = SigningKey::generate(&mut OsRng);
    forge.prank(SLASHER);
    forge.expect_revert("operator has no receipt pubkey");
    let _ = forge.call_slash_double_sign(
        OP,
        4,
        payload_a,
        &signed(&sk, payload_a),
        payload_b,
        &signed(&sk, payload_b),
    );
});

octra_test!(
    slash_double_sign_idempotent_after_already_slashed,
    |forge| {
        forge.deploy_octravpn(100, 10);
        forge.set_program_owner(OWNER);
        let op_sk = register_op_with_receipt_pubkey(&mut forge);

        let payload_a = "octravpn-receipt-v1|session=5|bytes=10|blind=a";
        let payload_b = "octravpn-receipt-v1|session=5|bytes=20|blind=b";
        let sig_a = signed(&op_sk, payload_a);
        let sig_b = signed(&op_sk, payload_b);

        forge.prank(SLASHER);
        forge
            .call_slash_double_sign(OP, 5, payload_a, &sig_a, payload_b, &sig_b)
            .expect("first slash");
        forge.prank(SLASHER);
        forge.expect_revert("already slashed");
        let _ = forge.call_slash_double_sign(OP, 5, payload_a, &sig_a, payload_b, &sig_b);
    }
);
