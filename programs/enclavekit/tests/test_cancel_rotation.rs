mod common;

use anchor_lang::error::ErrorCode;
use anchor_lang::prelude::Pubkey;
use common::{
    assert_failed_at, assert_program_error, vault_pda, CancelRotationRequest, EnclaveKey,
    EnclaveRequest, Env, TransferSolRequest, PROGRAM_INDEX,
};
use enclavekit::error::EnclaveKitError;
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
