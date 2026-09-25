mod common;

use common::{
    assert_program_error_at, confirm_rotation_instruction, vault_pda, EnclaveKey, EnclaveRequest,
    Env, ProposeRotationRequest, SetGuardiansRequest,
};
use enclavekit::{error::EnclaveKitError, state::Guardian, ROTATION_DELAY, ROTATION_WINDOW};
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use solana_signer::Signer;

const VAULT_FUNDING: u64 = 1_000_000_000;
const MAX_RELAYER_FEE: u64 = 100_000;
const RELAYER_FEE: u64 = 50_000;
/// Long enough for every authorization of a scenario, whatever the warp.
const AUTHORIZATION_TTL: i64 = ROTATION_DELAY + 2 * ROTATION_WINDOW;

/// `confirm_rotation` travels alone in its transaction.
const CONFIRM_INDEX: u8 = 0;

struct Scenario {
    env: Env,
    key: EnclaveKey,
    guardian: EnclaveKey,
    new_key: EnclaveKey,
    wallet_id: [u8; 32],
}

impl Scenario {
    /// Wallet created with one guardian, who then proposed `new_key`.
    /// The Clock has not moved since the proposal.
    fn with_pending_rotation() -> Self {
        let mut scenario = Self::new();
        scenario.propose();
        scenario
    }

    fn new() -> Self {
        let mut env = Env::new();
        let key = EnclaveKey::from_seed([7u8; 32]);
        let guardian = EnclaveKey::from_seed([9u8; 32]);
        let new_key = EnclaveKey::from_seed([11u8; 32]);
        let wallet_id = key.wallet_id();
        env.svm
            .airdrop(&vault_pda(&wallet_id), VAULT_FUNDING)
            .unwrap();

        let set_guardians = SetGuardiansRequest {
            wallet_id,
            guardians: [
                Guardian::P256(guardian.compressed_pubkey()),
                Guardian::None,
                Guardian::None,
            ],
            nonce: 0,
            expires_at: env.unix_timestamp() + AUTHORIZATION_TTL,
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        };
        let instructions = set_guardians.sign(&key, &env.payer.pubkey());
        env.send(&instructions)
            .unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs));

        Self {
            env,
            key,
            guardian,
            new_key,
            wallet_id,
        }
    }

    /// The guardian proposes `new_key`, using the wallet's current nonce.
    fn propose(&mut self) {
        let nonce = self.env.wallet(&self.wallet_id).unwrap().nonce;
        let request = ProposeRotationRequest {
            wallet_id: self.wallet_id,
            new_key: self.new_key.compressed_pubkey(),
            nonce,
            expires_at: self.env.unix_timestamp() + AUTHORIZATION_TTL,
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        };
        let instructions = request.sign(&self.guardian, &self.env.payer.pubkey());
        self.env
            .send(&instructions)
            .unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs));
    }

    fn confirm(&mut self) -> TransactionMetadata {
        self.try_confirm()
            .unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs))
    }

    fn try_confirm(&mut self) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        self.env
            .send(&[confirm_rotation_instruction(&self.wallet_id)])
    }
}

// The window: [proposed_at + ROTATION_DELAY, proposed_at + ROTATION_DELAY + ROTATION_WINDOW]

#[test]
fn rejects_before_the_delay_has_elapsed() {
    let mut scenario = Scenario::with_pending_rotation();
    scenario.env.warp(ROTATION_DELAY - 1);

    let failed = scenario.try_confirm().unwrap_err();
    assert_program_error_at(&failed, CONFIRM_INDEX, EnclaveKitError::RotationTooEarly);
}

#[test]
fn confirms_at_the_first_second_of_the_window() {
    let mut scenario = Scenario::with_pending_rotation();
    let nonce_before = scenario.env.wallet(&scenario.wallet_id).unwrap().nonce;
    scenario.env.warp(ROTATION_DELAY);

    scenario.confirm();

    let wallet = scenario.env.wallet(&scenario.wallet_id).unwrap();
    assert_eq!(wallet.active_key, scenario.new_key.compressed_pubkey());
    assert!(!wallet.attested);
    assert!(wallet.rotation.is_none());
    // Nobody signed a preimage: the counter does not move.
    assert_eq!(wallet.nonce, nonce_before);
    // The guardian list is untouched.
    assert_eq!(
        wallet.guardians[0],
        Guardian::P256(scenario.guardian.compressed_pubkey())
    );
}

#[test]
fn confirms_at_the_last_second_of_the_window() {
    let mut scenario = Scenario::with_pending_rotation();
    scenario.env.warp(ROTATION_DELAY + ROTATION_WINDOW);

    scenario.confirm();

    let wallet = scenario.env.wallet(&scenario.wallet_id).unwrap();
    assert_eq!(wallet.active_key, scenario.new_key.compressed_pubkey());
}

#[test]
fn rejects_once_the_window_has_closed() {
    let mut scenario = Scenario::with_pending_rotation();
    scenario.env.warp(ROTATION_DELAY + ROTATION_WINDOW + 1);

    let failed = scenario.try_confirm().unwrap_err();
    assert_program_error_at(&failed, CONFIRM_INDEX, EnclaveKitError::RotationExpired);
}

#[test]
fn rejects_without_a_pending_rotation() {
    let mut scenario = Scenario::new();
    scenario.env.warp(ROTATION_DELAY);

    let failed = scenario.try_confirm().unwrap_err();
    assert_program_error_at(&failed, CONFIRM_INDEX, EnclaveKitError::NoPendingRotation);
}

#[test]
fn cannot_be_confirmed_twice() {
    let mut scenario = Scenario::with_pending_rotation();
    scenario.env.warp(ROTATION_DELAY);
    scenario.confirm();

    let failed = scenario.try_confirm().unwrap_err();
    assert_program_error_at(&failed, CONFIRM_INDEX, EnclaveKitError::NoPendingRotation);
}

// After the swap

#[test]
fn the_new_key_acts_and_the_old_one_is_refused() {
    let mut scenario = Scenario::with_pending_rotation();
    scenario.env.warp(ROTATION_DELAY);
    scenario.confirm();

    let nonce = scenario.env.wallet(&scenario.wallet_id).unwrap().nonce;
    let another = EnclaveKey::from_seed([12u8; 32]);
    let request = ProposeRotationRequest {
        wallet_id: scenario.wallet_id,
        new_key: another.compressed_pubkey(),
        nonce,
        expires_at: scenario.env.unix_timestamp() + 60,
        max_relayer_fee: MAX_RELAYER_FEE,
        relayer_fee: RELAYER_FEE,
    };
    let relayer = scenario.env.payer.pubkey();

    let failed = scenario
        .env
        .send(&request.sign(&scenario.key, &relayer))
        .unwrap_err();
    assert_program_error_at(&failed, 1, EnclaveKitError::NotAGuardian);

    scenario
        .env
        .send(&request.sign(&scenario.new_key, &relayer))
        .unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs));
    let wallet = scenario.env.wallet(&scenario.wallet_id).unwrap();
    assert_eq!(wallet.active_key, another.compressed_pubkey());
}
