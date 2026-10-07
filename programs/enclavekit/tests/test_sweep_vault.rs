mod common;

use anchor_lang::prelude::Pubkey;
use common::{
    assert_program_error, vault_pda, wallet_pda, EnclaveKey, EnclaveRequest, Env,
    SetGuardiansRequest, SweepVaultRequest,
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
    request: SweepVaultRequest,
}

impl Scenario {
    fn new() -> Self {
        let mut env = Env::new();
        let key = EnclaveKey::from_seed([7u8; 32]);
        let wallet_id = key.wallet_id();
        env.svm
            .airdrop(&vault_pda(&wallet_id), VAULT_FUNDING)
            .unwrap();

        let request = SweepVaultRequest {
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

    fn try_send(
        &mut self,
        request: &SweepVaultRequest,
    ) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        let instructions = request.sign(&self.key, &self.relayer());
        self.env.send(&instructions)
    }

    /// Any enclave-authorised call that must pass, signed by `signer`.
    fn send_ok(
        &mut self,
        signer: &EnclaveKey,
        request: &impl EnclaveRequest,
    ) -> TransactionMetadata {
        let instructions = request.sign(signer, &self.relayer());
        self.env
            .send(&instructions)
            .unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs))
    }

    /// First action: names `guardian` in slot 0, so the state exists and
    /// its nonce is 1.
    fn name_guardian(&mut self, guardian: &EnclaveKey) {
        let set_guardians = SetGuardiansRequest {
            wallet_id: self.request.wallet_id,
            guardians: [
                Guardian::P256(guardian.compressed_pubkey()),
                Guardian::None,
                Guardian::None,
            ],
            nonce: 0,
            expires_at: self.request.expires_at,
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        };
        self.send_ok(&self.key.clone(), &set_guardians);
        self.request.nonce = 1;
    }
}

#[test]
fn first_action_empties_the_vault_and_creates_the_wallet() {
    let mut scenario = Scenario::new();
    let request = scenario.request.clone();
    let relayer = scenario.relayer();
    let relayer_before = scenario.env.balance(&relayer);

    let meta = scenario.send_ok(&scenario.key.clone(), &request);

    assert_eq!(scenario.vault(), 0);
    assert_eq!(
        scenario.env.balance(&request.to),
        VAULT_FUNDING - RELAYER_FEE
    );
    let wallet = scenario.env.wallet(&request.wallet_id).unwrap();
    assert_eq!(wallet.nonce, 1);
    // The relayer paid the transaction fee and the state rent, then got its
    // requested fee back from the vault.
    let rent = scenario.env.balance(&wallet_pda(&request.wallet_id));
    assert_eq!(
        scenario.env.balance(&relayer),
        relayer_before - meta.fee - rent + RELAYER_FEE
    );
}

#[test]
fn keeps_the_wallet_and_its_guardians() {
    let mut scenario = Scenario::new();
    let guardian = EnclaveKey::from_seed([9u8; 32]);
    scenario.name_guardian(&guardian);
    let request = scenario.request.clone();
    let vault_before = scenario.vault();

    scenario.send_ok(&scenario.key.clone(), &request);

    assert_eq!(scenario.vault(), 0);
    assert_eq!(
        scenario.env.balance(&request.to),
        vault_before - RELAYER_FEE
    );
    let wallet = scenario.env.wallet(&request.wallet_id).unwrap();
    assert_eq!(wallet.nonce, 2);
    assert_eq!(wallet.active_key, scenario.key.compressed_pubkey());
    assert_eq!(
        wallet.guardians[0],
        Guardian::P256(guardian.compressed_pubkey())
    );
}

#[test]
fn caps_the_refund_at_max_relayer_fee() {
    let mut scenario = Scenario::new();
    let greedy_relayer_request = SweepVaultRequest {
        relayer_fee: 2 * MAX_RELAYER_FEE,
        ..scenario.request.clone()
    };

    scenario.send_ok(&scenario.key.clone(), &greedy_relayer_request);

    // Whatever the relayer does not get goes to `to`.
    assert_eq!(scenario.vault(), 0);
    assert_eq!(
        scenario.env.balance(&greedy_relayer_request.to),
        VAULT_FUNDING - MAX_RELAYER_FEE
    );
}

#[test]
fn rejects_when_the_refund_exceeds_the_balance() {
    let mut scenario = Scenario::new();
    let request = SweepVaultRequest {
        max_relayer_fee: VAULT_FUNDING + 1,
        relayer_fee: VAULT_FUNDING + 1,
        ..scenario.request.clone()
    };

    let failed = scenario.try_send(&request).unwrap_err();
    assert_program_error(&failed, EnclaveKitError::InsufficientVaultBalance);
}

#[test]
fn rejects_the_same_signature_after_a_new_deposit() {
    // The amount is not signed: without the nonce, anyone could send the
    // same transaction again after each deposit until it expires.
    let mut scenario = Scenario::new();
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

    let failed = scenario.env.send(&instructions).unwrap_err();
    assert_program_error(&failed, EnclaveKitError::NonceMismatch);
    assert_eq!(scenario.vault(), VAULT_FUNDING);
}

#[test]
fn rejects_a_guardian_sweeping() {
    let mut scenario = Scenario::new();
    let guardian = EnclaveKey::from_seed([9u8; 32]);
    scenario.name_guardian(&guardian);
    let request = scenario.request.clone();

    let instructions = request.sign(&guardian, &scenario.relayer());
    let failed = scenario.env.send(&instructions).unwrap_err();
    assert_program_error(&failed, EnclaveKitError::KeyMismatch);
}
