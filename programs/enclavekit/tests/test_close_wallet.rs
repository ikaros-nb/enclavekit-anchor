mod common;

use anchor_lang::error::ErrorCode;
use anchor_lang::prelude::Pubkey;
use common::{
    assert_failed_at, assert_program_error, vault_pda, wallet_pda, CloseWalletRequest, EnclaveKey,
    EnclaveRequest, Env, SetGuardiansRequest, SweepVaultRequest, PROGRAM_INDEX,
};
use enclavekit::{error::EnclaveKitError, state::Guardian};
use litesvm::types::TransactionMetadata;
use solana_signer::Signer;

const VAULT_FUNDING: u64 = 1_000_000_000;
const MAX_RELAYER_FEE: u64 = 100_000;
const RELAYER_FEE: u64 = 50_000;

struct Scenario {
    env: Env,
    key: EnclaveKey,
    request: CloseWalletRequest,
}

impl Scenario {
    fn new() -> Self {
        let mut env = Env::new();
        let key = EnclaveKey::from_seed([7u8; 32]);
        let wallet_id = key.wallet_id();
        env.svm
            .airdrop(&vault_pda(&wallet_id), VAULT_FUNDING)
            .unwrap();

        let request = CloseWalletRequest {
            wallet_id,
            to: Pubkey::new_unique(),
            nonce: 0,
            expires_at: env.unix_timestamp() + 60,
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        };
        Self { env, key, request }
    }

    fn relayer(&self) -> Pubkey {
        self.env.payer.pubkey()
    }

    fn vault(&self) -> u64 {
        self.env.balance(&vault_pda(&self.request.wallet_id))
    }

    fn state_rent(&self) -> u64 {
        self.env.balance(&wallet_pda(&self.request.wallet_id))
    }

    /// Closed accounts hold 0 lamports, and the runtime drops them.
    fn state_is_closed(&self) -> bool {
        self.env
            .svm
            .get_account(&wallet_pda(&self.request.wallet_id))
            .is_none_or(|account| account.lamports == 0)
    }

    /// Any enclave-authorised call that must pass, signed by `signer`.
    /// Advances the nonce of the request under test.
    fn send_ok(
        &mut self,
        signer: &EnclaveKey,
        request: &impl EnclaveRequest,
    ) -> TransactionMetadata {
        let instructions = request.sign(signer, &self.relayer());
        let meta = self
            .env
            .send(&instructions)
            .unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs));
        self.request.nonce += 1;
        meta
    }

    /// First action: names a guardian in slot 0, so the state exists and its
    /// nonce is 1. Returns the guardian's key.
    fn create_wallet(&mut self) -> EnclaveKey {
        let guardian = EnclaveKey::from_seed([9u8; 32]);
        let set_guardians = SetGuardiansRequest {
            wallet_id: self.request.wallet_id,
            guardians: [
                Guardian::P256(guardian.compressed_pubkey()),
                Guardian::None,
                Guardian::None,
            ],
            nonce: self.request.nonce,
            expires_at: self.request.expires_at,
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        };
        self.send_ok(&self.key.clone(), &set_guardians);
        guardian
    }

    /// Sends the whole vault elsewhere first.
    fn empty_vault(&mut self) {
        let sweep = SweepVaultRequest {
            wallet_id: self.request.wallet_id,
            to: Pubkey::new_unique(),
            nonce: self.request.nonce,
            expires_at: self.request.expires_at,
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        };
        self.send_ok(&self.key.clone(), &sweep);
        assert_eq!(self.vault(), 0);
    }
}

#[test]
fn closes_the_wallet_and_sends_everything_out() {
    let mut scenario = Scenario::new();
    scenario.create_wallet();
    let request = scenario.request.clone();
    let relayer = scenario.relayer();
    let relayer_before = scenario.env.balance(&relayer);
    let vault_before = scenario.vault();
    let state_rent = scenario.state_rent();

    let meta = scenario.send_ok(&scenario.key.clone(), &request);

    assert!(scenario.state_is_closed());
    assert_eq!(scenario.vault(), 0);
    assert_eq!(
        scenario.env.balance(&request.to),
        vault_before - RELAYER_FEE
    );
    // The relayer gets its fee back, and the rent it advanced for the state.
    assert_eq!(
        scenario.env.balance(&relayer),
        relayer_before - meta.fee + RELAYER_FEE + state_rent
    );
}

#[test]
fn closes_a_wallet_whose_vault_is_empty() {
    let mut scenario = Scenario::new();
    scenario.create_wallet();
    scenario.empty_vault();
    let request = scenario.request.clone();
    let relayer = scenario.relayer();
    let relayer_before = scenario.env.balance(&relayer);
    let state_rent = scenario.state_rent();

    let meta = scenario.send_ok(&scenario.key.clone(), &request);

    assert!(scenario.state_is_closed());
    assert_eq!(scenario.env.balance(&request.to), 0);
    // No refund from an empty vault: the state's rent alone pays the relayer.
    assert_eq!(
        scenario.env.balance(&relayer),
        relayer_before - meta.fee + state_rent
    );
}

#[test]
fn caps_the_refund_at_max_relayer_fee() {
    let mut scenario = Scenario::new();
    scenario.create_wallet();
    let greedy_relayer_request = CloseWalletRequest {
        relayer_fee: 2 * MAX_RELAYER_FEE,
        ..scenario.request.clone()
    };
    let relayer = scenario.relayer();
    let relayer_before = scenario.env.balance(&relayer);
    let vault_before = scenario.vault();
    let state_rent = scenario.state_rent();

    let meta = scenario.send_ok(&scenario.key.clone(), &greedy_relayer_request);

    assert_eq!(
        scenario.env.balance(&greedy_relayer_request.to),
        vault_before - MAX_RELAYER_FEE
    );
    assert_eq!(
        scenario.env.balance(&relayer),
        relayer_before - meta.fee + MAX_RELAYER_FEE + state_rent
    );
}

#[test]
fn rejects_a_wallet_that_does_not_exist() {
    // No `init_if_needed` here: Anchor refuses the empty PDA before the handler runs.
    let mut scenario = Scenario::new();
    let request = scenario.request.clone();

    let instructions = request.sign(&scenario.key, &scenario.relayer());
    let failed = scenario.env.send(&instructions).unwrap_err();
    let code = ErrorCode::AccountNotInitialized as u32;
    assert_failed_at(&failed, PROGRAM_INDEX, &format!("Custom({code})"));
    assert_eq!(scenario.vault(), VAULT_FUNDING);
}

#[test]
fn rejects_the_same_signature_after_closing() {
    let mut scenario = Scenario::new();
    scenario.create_wallet();
    let instructions = scenario.request.sign(&scenario.key, &scenario.relayer());
    scenario
        .env
        .send(&instructions)
        .unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs));
    scenario
        .env
        .svm
        .airdrop(&vault_pda(&scenario.request.wallet_id), VAULT_FUNDING)
        .unwrap();

    // The state is gone with its nonce: nothing left to authorise against.
    let failed = scenario.env.send(&instructions).unwrap_err();
    let code = ErrorCode::AccountNotInitialized as u32;
    assert_failed_at(&failed, PROGRAM_INDEX, &format!("Custom({code})"));
    assert_eq!(scenario.vault(), VAULT_FUNDING);
}

#[test]
fn rejects_a_guardian_closing() {
    let mut scenario = Scenario::new();
    let guardian = scenario.create_wallet();
    let request = scenario.request.clone();

    let instructions = request.sign(&guardian, &scenario.relayer());
    let failed = scenario.env.send(&instructions).unwrap_err();
    assert_program_error(&failed, EnclaveKitError::KeyMismatch);
    assert!(!scenario.state_is_closed());
}
