mod common;

use anchor_lang::error::ErrorCode;
use anchor_lang::prelude::Pubkey;
use common::{
    assert_failed_at, assert_program_error, vault_pda, CancelRotationRequest, EnclaveKey,
    EnclaveRequest, Env, ProposeRotationRequest, SetGuardiansRequest, TransferSolRequest,
    PROGRAM_INDEX,
};
use enclavekit::{error::EnclaveKitError, state::Guardian};
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use solana_signer::Signer;

const VAULT_FUNDING: u64 = 1_000_000_000;
const MAX_RELAYER_FEE: u64 = 100_000;
const RELAYER_FEE: u64 = 50_000;

struct Scenario {
    env: Env,
    key: EnclaveKey,
    request: CancelRotationRequest,
}

impl Scenario {
    fn new() -> Self {
        let mut env = Env::new();
        let key = EnclaveKey::from_seed([7u8; 32]);
        let wallet_id = key.wallet_id();
        env.svm
            .airdrop(&vault_pda(&wallet_id), VAULT_FUNDING)
            .unwrap();

        let request = CancelRotationRequest {
            wallet_id,
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

    /// Creates the state PDA with a first action, so the wallet exists and
    /// its nonce is 1.
    fn create_wallet(&mut self) {
        let request = TransferSolRequest {
            wallet_id: self.request.wallet_id,
            to: Pubkey::new_unique(),
            lamports: 1_000_000,
            nonce: 0,
            expires_at: self.request.expires_at,
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        };
        let instructions = request.sign(&self.key, &self.relayer());
        self.env
            .send(&instructions)
            .unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs));
        self.request.nonce = 1;
    }

    fn try_send(
        &mut self,
        request: &CancelRotationRequest,
    ) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        let instructions = request.sign(&self.key, &self.relayer());
        self.env.send(&instructions)
    }

    /// Any enclave-authorised call that must pass, signed by `signer`.
    fn send_ok(&mut self, signer: &EnclaveKey, request: &impl EnclaveRequest) {
        let instructions = request.sign(signer, &self.relayer());
        self.env
            .send(&instructions)
            .unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs));
        self.request.nonce += 1;
    }

    /// Registers `guardian` in slot 0 and has it propose a rotation, so the
    /// wallet carries a pending rotation. Uses and advances the nonce.
    fn pending_rotation_from(&mut self, guardian: &EnclaveKey) {
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

        let propose = ProposeRotationRequest {
            wallet_id: self.request.wallet_id,
            new_key: EnclaveKey::from_seed([11u8; 32]).compressed_pubkey(),
            nonce: self.request.nonce,
            expires_at: self.request.expires_at,
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        };
        self.send_ok(guardian, &propose);
    }
}

#[test]
fn active_key_cancels_a_guardians_proposal() {
    let mut scenario = Scenario::new();
    scenario.create_wallet();
    let guardian = EnclaveKey::from_seed([9u8; 32]);
    scenario.pending_rotation_from(&guardian);
    let request = scenario.request.clone();
    let relayer = scenario.relayer();
    let relayer_before = scenario.env.balance(&relayer);
    let vault_before = scenario.env.balance(&vault_pda(&request.wallet_id));

    let meta = scenario
        .try_send(&request)
        .unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs));

    let wallet = scenario.env.wallet(&request.wallet_id).unwrap();
    assert!(wallet.rotation.is_none());
    assert_eq!(wallet.nonce, request.nonce + 1);
    // Cancelling changes nothing else: same key, same guardians.
    assert_eq!(wallet.active_key, scenario.key.compressed_pubkey());
    assert_eq!(
        wallet.guardians[0],
        Guardian::P256(guardian.compressed_pubkey())
    );
    // Only the refund leaves the vault; the state PDA already existed.
    assert_eq!(
        scenario.env.balance(&vault_pda(&request.wallet_id)),
        vault_before - RELAYER_FEE
    );
    assert_eq!(
        scenario.env.balance(&relayer),
        relayer_before - meta.fee + RELAYER_FEE
    );
}

#[test]
fn rejects_a_guardian_cancelling() {
    let mut scenario = Scenario::new();
    scenario.create_wallet();
    let guardian = EnclaveKey::from_seed([9u8; 32]);
    scenario.pending_rotation_from(&guardian);
    let request = scenario.request.clone();

    let instructions = request.sign(&guardian, &scenario.relayer());
    let failed = scenario.env.send(&instructions).unwrap_err();
    assert_program_error(&failed, EnclaveKitError::KeyMismatch);
}

#[test]
fn rejects_without_a_pending_rotation() {
    let mut scenario = Scenario::new();
    scenario.create_wallet();
    let request = scenario.request.clone();

    let failed = scenario.try_send(&request).unwrap_err();
    assert_program_error(&failed, EnclaveKitError::NoPendingRotation);
}

#[test]
fn rejects_a_wallet_that_does_not_exist() {
    // No `init_if_needed` here: Anchor refuses the empty PDA before the handler runs.
    let mut scenario = Scenario::new();
    let request = scenario.request.clone();

    let failed = scenario.try_send(&request).unwrap_err();
    let code = ErrorCode::AccountNotInitialized as u32;
    assert_failed_at(&failed, PROGRAM_INDEX, &format!("Custom({code})"));
}
