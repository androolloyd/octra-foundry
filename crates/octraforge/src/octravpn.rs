//! Domain helpers for the `OctraVPN` AML program.
//!
//! Builds canonical JSON envelopes matching the AML method signatures
//! in `program/main.aml` and submits them via [`ForgeCtx::submit`].
//! Mirrors what a real client SDK would build.

use serde_json::{json, Value};

use crate::{ForgeCtx, SubmitError, SubmitResult};

/// Default address used as `from` when no prank is active.
pub const DEFAULT_CALLER: &str = "octFORGEDEFAULTCALLER000000000000000000001";

/// Stand-in HFHE pubkey + zero-ciphertext used by tests. Real Octra
/// keys are produced by the operator's wallet; the mock just stores
/// the bytes opaquely.
pub const MOCK_HFHE_PUBKEY: &str =
    "fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe";
pub const MOCK_INITIAL_ENC_ZERO: &str =
    "00000000000000000000000000000000000000000000000000000000000000ab";

impl ForgeCtx {
    /// "Deploy" `OctraVPN`. The mock returns hard-coded params today;
    /// this is a no-op that returns the program address (matching
    /// Foundry's `forge.deploy_contract(...)` ergonomics).
    pub fn deploy_octravpn(
        &mut self,
        _min_session_deposit: u64,
        _min_tailnet_deposit: u64,
    ) -> String {
        self.program_addr.clone()
    }

    /// Mark `addr` as an Octra protocol validator on the mock chain
    /// AND seed enough stake for `register_endpoint` to succeed. The
    /// AML no longer gates on validator status (uses stake), but
    /// keeping both turn-ons here keeps existing tests un-churned.
    pub fn become_octra_validator(&mut self, addr: &str) {
        self.app.add_octra_validator(addr);
        self.app
            .seed_endpoint_stake(addr, octra_mock_rpc::MIN_ENDPOINT_STAKE);
    }

    /// Seed `addr` with `amount` OU of operator stake, skipping the
    /// real `bond_endpoint` tx.
    pub fn seed_endpoint_stake(&mut self, addr: &str, amount: u64) {
        self.app.seed_endpoint_stake(addr, amount);
    }

    /// Set the program owner (governance wallet). Tests that exercise
    /// `gov_slash_operator` / `withdraw_program_treasury` need this.
    pub fn set_program_owner(&mut self, addr: &str) {
        self.app.set_owner(addr);
    }

    /// `bond_endpoint()` — value-bearing.
    pub fn call_bond_endpoint(&mut self, amount: u64) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "bond_endpoint",
            "params": [],
            "value": amount,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `unbond_endpoint()`.
    pub fn call_unbond_endpoint(&mut self) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "unbond_endpoint",
            "params": [],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `finalize_unbond()`.
    pub fn call_finalize_unbond(&mut self) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "finalize_unbond",
            "params": [],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `gov_slash_operator(operator_addr, reason)`. Owner only.
    pub fn call_gov_slash_operator(
        &mut self,
        operator: &str,
        reason: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "gov_slash_operator",
            "params": [operator, reason],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `register_endpoint(endpoint, wg_pubkey, hfhe_pubkey, initial_enc_zero, region, price_per_mb, receipt_pubkey)`.
    ///
    /// Caller must have at least `MIN_ENDPOINT_STAKE` bonded.
    /// `receipt_pubkey` is the ed25519 pubkey the operator uses to
    /// sign off-chain receipts; needed for `slash_double_sign` to be
    /// useful. Pass an empty string if you only want the bond/register
    /// path tested.
    #[allow(clippy::too_many_arguments)]
    pub fn call_register_endpoint(
        &mut self,
        endpoint: &str,
        wg_pubkey_hex: &str,
        hfhe_pubkey_hex: &str,
        initial_enc_zero_hex: &str,
        region: &str,
        price_per_mb: u64,
        receipt_pubkey: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "register_endpoint",
            "params": [
                endpoint,
                wg_pubkey_hex,
                hfhe_pubkey_hex,
                initial_enc_zero_hex,
                region,
                price_per_mb,
                receipt_pubkey,
            ],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// Convenience over `call_register_endpoint` using mock HFHE values
    /// and an empty `receipt_pubkey` (the off-chain dual-sig slash path
    /// is disabled — use `call_register_endpoint` directly to enable).
    pub fn call_register_endpoint_simple(
        &mut self,
        endpoint: &str,
        wg_pubkey_hex: &str,
        region: &str,
        price_per_mb: u64,
    ) -> Result<SubmitResult, SubmitError> {
        self.call_register_endpoint(
            endpoint,
            wg_pubkey_hex,
            MOCK_HFHE_PUBKEY,
            MOCK_INITIAL_ENC_ZERO,
            region,
            price_per_mb,
            "",
        )
    }

    /// `slash_double_sign(operator, session_id, payload_a, sig_a, payload_b, sig_b)`.
    ///
    /// The slasher (= caller) collects two ed25519-signed receipt
    /// payloads from `operator`'s off-chain signing key with the same
    /// `session_id` but different `bytes_used` / `blind`. Verifying
    /// both sigs under the registered `receipt_pubkey` is sufficient
    /// evidence; the AML slashes 90% to treasury / 10% bounty to
    /// caller.
    #[allow(clippy::too_many_arguments)]
    pub fn call_slash_double_sign(
        &mut self,
        operator: &str,
        session_id: u64,
        payload_a_hex: &str,
        sig_a_hex: &str,
        payload_b_hex: &str,
        sig_b_hex: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "slash_double_sign",
            "params": [
                operator,
                session_id,
                payload_a_hex,
                sig_a_hex,
                payload_b_hex,
                sig_b_hex,
            ],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `update_endpoint(endpoint, region, price_per_mb)`.
    pub fn call_update_endpoint(
        &mut self,
        endpoint: &str,
        region: &str,
        price_per_mb: u64,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "update_endpoint",
            "params": [endpoint, region, price_per_mb],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `rotate_keys(new_wg, new_hfhe, new_initial_enc_zero)`.
    pub fn call_rotate_keys(
        &mut self,
        new_wg_pubkey_hex: &str,
        new_hfhe_pubkey_hex: &str,
        new_initial_enc_zero_hex: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "rotate_keys",
            "params": [
                new_wg_pubkey_hex,
                new_hfhe_pubkey_hex,
                new_initial_enc_zero_hex,
            ],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `retire_endpoint()`.
    pub fn call_retire_endpoint(&mut self) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "retire_endpoint",
            "params": [],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `create_tailnet(acl_policy)` — `value` is the initial treasury.
    pub fn call_create_tailnet(
        &mut self,
        acl_policy_hex: &str,
        treasury: u64,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "create_tailnet",
            "params": [acl_policy_hex],
            "value": treasury,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `add_member(tailnet_id, member)`.
    pub fn call_add_member(
        &mut self,
        tailnet_id: u64,
        member: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "add_member",
            "params": [tailnet_id, member],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `remove_member(tailnet_id, member)`.
    pub fn call_remove_member(
        &mut self,
        tailnet_id: u64,
        member: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "remove_member",
            "params": [tailnet_id, member],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `deposit_to_tailnet(tailnet_id)` — `value` is the deposit amount.
    pub fn call_deposit_to_tailnet(
        &mut self,
        tailnet_id: u64,
        amount: u64,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "deposit_to_tailnet",
            "params": [tailnet_id],
            "value": amount,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `configure_tailnet_exit(tailnet_id, exit_addr)`.
    pub fn call_configure_tailnet_exit(
        &mut self,
        tailnet_id: u64,
        exit_addr: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "configure_tailnet_exit",
            "params": [tailnet_id, exit_addr],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `update_acl(tailnet_id, new_acl_policy)`.
    pub fn call_update_acl(
        &mut self,
        tailnet_id: u64,
        new_acl_hex: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "update_acl",
            "params": [tailnet_id, new_acl_hex],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `open_session(tailnet_id, exit_addr, max_pay)` — single-hop in v1.
    pub fn call_open_session(
        &mut self,
        tailnet_id: u64,
        exit_addr: &str,
        max_pay: u64,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "open_session",
            "params": [tailnet_id, exit_addr, max_pay],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `settle_claim(session_id, bytes_used)` — operator-side call.
    /// Records the operator's bytes_used claim; equivocation here
    /// (same session, different bytes from same caller) triggers an
    /// in-AML slash.
    pub fn call_settle_claim(
        &mut self,
        session_id: u64,
        bytes_used: u64,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "settle_claim",
            "params": [session_id, bytes_used],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `settle_confirm(session_id, bytes_used)` — client-side call.
    /// Only the session opener can call. If the bytes_used matches the
    /// operator's claim, settlement applies and emits `SessionSettled`.
    /// If it doesn't, a `SettleDispute` event is recorded and the
    /// session stays open.
    pub fn call_settle_confirm(
        &mut self,
        session_id: u64,
        bytes_used: u64,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "settle_confirm",
            "params": [session_id, bytes_used],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `precommit_join_token(tailnet_id, sha256_hex)` — owner-only.
    /// Publishes a sha256 commitment that any holder of the preimage
    /// can later redeem to join the tailnet.
    pub fn call_precommit_join_token(
        &mut self,
        tailnet_id: u64,
        token_hash_hex: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "precommit_join_token",
            "params": [tailnet_id, token_hash_hex],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `redeem_join_token(tailnet_id, preimage_hex)` — anyone with the
    /// preimage can redeem. On success the caller is added as a
    /// tailnet member.
    pub fn call_redeem_join_token(
        &mut self,
        tailnet_id: u64,
        preimage_hex: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "redeem_join_token",
            "params": [tailnet_id, preimage_hex],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `claim_no_show(session_id)`.
    pub fn call_claim_no_show(&mut self, session_id: u64) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "claim_no_show",
            "params": [session_id],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `sweep_expired_session(session_id)`.
    pub fn call_sweep_expired_session(
        &mut self,
        session_id: u64,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "sweep_expired_session",
            "params": [session_id],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `claim_earnings(amount, proof)` — verifies FHE zero-proof.
    /// The mock simplifies the proof to an exact-equality check.
    pub fn call_claim_earnings(
        &mut self,
        amount: u64,
        proof_hex: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "claim_earnings",
            "params": [amount, proof_hex],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `withdraw_program_treasury(to, amount)`. Owner only.
    pub fn call_withdraw_program_treasury(
        &mut self,
        to: &str,
        amount: u64,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "withdraw_program_treasury",
            "params": [to, amount],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `register_device(device_addr)`.
    pub fn call_register_device(&mut self, device: &str) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "register_device",
            "params": [device],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `revoke_device(device_addr)`.
    pub fn call_revoke_device(&mut self, device: &str) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "revoke_device",
            "params": [device],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    // ============== v2 helpers ====================================
    //
    // The v2 OctraVPN program splits operator/proxy roles, supports
    // multi-class billing (shared vs internal traffic), and lets the
    // tailnet owner authorize specific proxy addresses. The mock-rpc
    // dispatches v2 methods by exact name (`_v2` suffix where needed).

    /// "Deploy" `OctraVPN` v2. Like the v1 deploy this is a no-op that
    /// returns the program address; the mock distinguishes v1 from v2
    /// by the method suffix on incoming calls, not by deploy site.
    pub fn deploy_octravpn_v2(
        &mut self,
        _min_session_deposit: u64,
        _min_tailnet_deposit: u64,
    ) -> String {
        self.program_addr.clone()
    }

    /// `authorize_proxy(tailnet_id, proxy_addr)` — tailnet-owner only.
    /// Grants `proxy_addr` permission to serve sessions on the named
    /// tailnet.
    pub fn call_authorize_proxy(
        &mut self,
        tailnet_id: u64,
        proxy_addr: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "authorize_proxy",
            "params": [tailnet_id, proxy_addr],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `revoke_proxy(tailnet_id, proxy_addr)` — tailnet-owner only.
    pub fn call_revoke_proxy(
        &mut self,
        tailnet_id: u64,
        proxy_addr: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "revoke_proxy",
            "params": [tailnet_id, proxy_addr],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `set_charge_internal_traffic(tailnet_id, charge)` — toggle billing
    /// for class=internal sessions on this tailnet. `charge = 0` means
    /// internal traffic is free; `charge = 1` means bill at the same
    /// per-MB rate as shared traffic.
    pub fn call_set_charge_internal_traffic(
        &mut self,
        tailnet_id: u64,
        charge: u64,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "set_charge_internal_traffic",
            "params": [tailnet_id, charge],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `open_session_v2(tailnet_id, proxy_addr, class, price_per_mb, max_pay)`.
    ///
    /// `class` is `0` for shared traffic (billed) and `1` for internal
    /// traffic (subject to the per-tailnet toggle).
    pub fn call_open_session_v2(
        &mut self,
        tailnet_id: u64,
        proxy_addr: &str,
        class: u64,
        price_per_mb: u64,
        max_pay: u64,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "open_session_v2",
            "params": [tailnet_id, proxy_addr, class, price_per_mb, max_pay],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `settle_claim_v2(session_id, bytes_used)` — proxy-side claim
    /// for a v2 session.
    pub fn call_settle_claim_v2(
        &mut self,
        session_id: u64,
        bytes_used: u64,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "settle_claim_v2",
            "params": [session_id, bytes_used],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `settle_confirm_v2(session_id, bytes_used)` — client-side
    /// confirmation for a v2 session. Matching bytes apply settlement
    /// (`SessionSettled`); mismatched bytes record a dispute and leave
    /// the session open.
    pub fn call_settle_confirm_v2(
        &mut self,
        session_id: u64,
        bytes_used: u64,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "settle_confirm_v2",
            "params": [session_id, bytes_used],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `proxy_register_keys(hfhe_pubkey, initial_enc_zero)` — proxies
    /// publish their HFHE encryption material so the program can route
    /// encrypted earnings to them. Mirrors the operator-side key
    /// portion of v1's `register_endpoint`.
    pub fn call_proxy_register_keys(
        &mut self,
        hfhe_pubkey: &str,
        initial_enc_zero: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "proxy_register_keys",
            "params": [hfhe_pubkey, initial_enc_zero],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }
}

// Suppress unused-import warning when `Value` isn't otherwise referenced.
#[allow(dead_code)]
const _: fn() -> Value = || Value::Null;
