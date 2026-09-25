mod common;

use anchor_lang::prelude::Pubkey;
use common::{
    assert_program_error, vault_pda, EnclaveKey, EnclaveRequest, Env, ProposeRotationRequest,
    SetGuardiansRequest,
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
    /// Guardian slots 0 and 1.
    guardians: [EnclaveKey; 2],
    /// The replacement device.
    new_key: EnclaveKey,
    /// Valid for the active key right after `new()`.
    request: ProposeRotationRequest,
}

impl Scenario {
    /// Creates the wallet with two guardians, so the next nonce is 1.
    fn new() -> Self {
        let mut env = Env::new();
        let key = EnclaveKey::from_seed([7u8; 32]);
        let guardians = [
            EnclaveKey::from_seed([9u8; 32]),
            EnclaveKey::from_seed([10u8; 32]),
        ];
        let new_key = EnclaveKey::from_seed([11u8; 32]);
        let wallet_id = key.wallet_id();
        env.svm
            .airdrop(&vault_pda(&wallet_id), VAULT_FUNDING)
            .unwrap();
        let expires_at = env.unix_timestamp() + 60;

        let set_guardians = SetGuardiansRequest {
            wallet_id,
            guardians: [
                Guardian::P256(guardians[0].compressed_pubkey()),
                Guardian::P256(guardians[1].compressed_pubkey()),
                Guardian::None,
            ],
            nonce: 0,
            expires_at,
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        };
        let instructions = set_guardians.sign(&key, &env.payer.pubkey());
        env.send(&instructions)
            .unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs));

        let request = ProposeRotationRequest {
            wallet_id,
            new_key: new_key.compressed_pubkey(),
            nonce: 1,
            expires_at,
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        };
        Self {
            env,
            key,
            guardians,
            new_key,
            request,
        }
    }

    fn relayer(&self) -> Pubkey {
        self.env.payer.pubkey()
    }

    /// Happy-path send signed by `signer`: panics with the logs on failure.
    fn send_as(
        &mut self,
        signer: &EnclaveKey,
        request: &ProposeRotationRequest,
    ) -> TransactionMetadata {
        self.try_send_as(signer, request)
            .unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs))
    }

    fn try_send_as(
        &mut self,
        signer: &EnclaveKey,
        request: &ProposeRotationRequest,
    ) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        let instructions = request.sign(signer, &self.relayer());
        self.env.send(&instructions)
    }
}

// Active key path

#[test]
fn active_key_rotates_immediately() {
    let mut scenario = Scenario::new();
    let request = scenario.request.clone();
    let key = scenario.key.clone();

    scenario.send_as(&key, &request);

    let wallet = scenario.env.wallet(&request.wallet_id).unwrap();
    assert_eq!(wallet.active_key, scenario.new_key.compressed_pubkey());
    assert!(!wallet.attested);
    assert!(wallet.rotation.is_none());
    assert_eq!(wallet.nonce, 2);
    // Guardians survive a rotation.
    assert_eq!(
        wallet.guardians[0],
        Guardian::P256(scenario.guardians[0].compressed_pubkey())
    );
}

#[test]
fn the_new_key_signs_the_next_action_and_the_old_one_cannot() {
    let mut scenario = Scenario::new();
    let first = scenario.request.clone();
    let old_key = scenario.key.clone();
    scenario.send_as(&old_key, &first);

    let again = EnclaveKey::from_seed([12u8; 32]);
    let second = ProposeRotationRequest {
        nonce: 2,
        new_key: again.compressed_pubkey(),
        ..first
    };
    let failed = scenario.try_send_as(&old_key, &second).unwrap_err();
    assert_program_error(&failed, EnclaveKitError::NotAGuardian);

    let new_key = scenario.new_key.clone();
    scenario.send_as(&new_key, &second);
    let wallet = scenario.env.wallet(&second.wallet_id).unwrap();
    assert_eq!(wallet.active_key, again.compressed_pubkey());
}

// Guardian path

#[test]
fn guardian_writes_a_pending_rotation() {
    let mut scenario = Scenario::new();
    let request = scenario.request.clone();
    let guardian = scenario.guardians[0].clone();
    let key = scenario.key.clone();

    scenario.send_as(&guardian, &request);

    let wallet = scenario.env.wallet(&request.wallet_id).unwrap();
    // Nothing changes yet, the timelock runs.
    assert_eq!(wallet.active_key, key.compressed_pubkey());
    assert_eq!(wallet.nonce, 2);
    let pending = wallet.rotation.expect("the guardian's proposal is stored");
    assert_eq!(pending.new_key, request.new_key);
    assert_eq!(pending.proposed_by, 0);
    assert_eq!(pending.proposed_at, scenario.env.unix_timestamp());
}

#[test]
fn guardian_replaces_its_own_proposal() {
    let mut scenario = Scenario::new();
    let first = scenario.request.clone();
    let guardian = scenario.guardians[1].clone();
    scenario.send_as(&guardian, &first);

    let other_device = EnclaveKey::from_seed([12u8; 32]);
    let second = ProposeRotationRequest {
        nonce: 2,
        new_key: other_device.compressed_pubkey(),
        ..first
    };
    scenario.send_as(&guardian, &second);

    let pending = scenario
        .env
        .wallet(&second.wallet_id)
        .unwrap()
        .rotation
        .unwrap();
    assert_eq!(pending.new_key, second.new_key);
    assert_eq!(pending.proposed_by, 1);
}

#[test]
fn rejects_a_guardian_replacing_another_guardians_proposal() {
    let mut scenario = Scenario::new();
    let first = scenario.request.clone();
    scenario.send_as(&scenario.guardians[0].clone(), &first);

    let second = ProposeRotationRequest { nonce: 2, ..first };
    let failed = scenario
        .try_send_as(&scenario.guardians[1].clone(), &second)
        .unwrap_err();
    assert_program_error(&failed, EnclaveKitError::RotationSlotTaken);
}

#[test]
fn active_key_clears_a_guardians_proposal() {
    let mut scenario = Scenario::new();
    let first = scenario.request.clone();
    scenario.send_as(&scenario.guardians[0].clone(), &first);

    let second = ProposeRotationRequest { nonce: 2, ..first };
    scenario.send_as(&scenario.key.clone(), &second);

    let wallet = scenario.env.wallet(&second.wallet_id).unwrap();
    assert!(wallet.rotation.is_none());
    assert_eq!(wallet.active_key, second.new_key);
}

// Refusals

#[test]
fn rejects_a_key_that_is_neither_active_nor_guardian() {
    let mut scenario = Scenario::new();
    let request = scenario.request.clone();
    let stranger = EnclaveKey::from_seed([13u8; 32]);

    let failed = scenario.try_send_as(&stranger, &request).unwrap_err();
    assert_program_error(&failed, EnclaveKitError::NotAGuardian);
}

#[test]
fn rejects_an_all_zero_new_key() {
    let mut scenario = Scenario::new();
    let request = ProposeRotationRequest {
        new_key: [0u8; 33],
        ..scenario.request.clone()
    };

    let failed = scenario
        .try_send_as(&scenario.key.clone(), &request)
        .unwrap_err();
    assert_program_error(&failed, EnclaveKitError::InvalidNewKey);
}
