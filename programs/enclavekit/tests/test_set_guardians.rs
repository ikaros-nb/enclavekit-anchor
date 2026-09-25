mod common;

use anchor_lang::prelude::Pubkey;
use common::{
    assert_program_error, vault_pda, wallet_pda, EnclaveKey, EnclaveRequest, Env,
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
    /// The second Apple device.
    guardian: EnclaveKey,
    request: SetGuardiansRequest,
}

impl Scenario {
    fn new() -> Self {
        let mut env = Env::new();
        let key = EnclaveKey::from_seed([7u8; 32]);
        let guardian = EnclaveKey::from_seed([9u8; 32]);
        let wallet_id = key.wallet_id();
        env.svm
            .airdrop(&vault_pda(&wallet_id), VAULT_FUNDING)
            .unwrap();

        let request = SetGuardiansRequest {
            wallet_id,
            guardians: [
                Guardian::P256(guardian.compressed_pubkey()),
                Guardian::None,
                Guardian::None,
            ],
            nonce: 0,
            expires_at: env.unix_timestamp() + 60,
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        };
        Self {
            env,
            key,
            guardian,
            request,
        }
    }

    fn relayer(&self) -> Pubkey {
        self.env.payer.pubkey()
    }

    /// Happy-path send: panics with the logs if the transaction fails.
    fn send(&mut self, request: &SetGuardiansRequest) -> TransactionMetadata {
        self.try_send(request)
            .unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs))
    }

    fn try_send(
        &mut self,
        request: &SetGuardiansRequest,
    ) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        let instructions = request.sign(&self.key, &self.relayer());
        self.env.send(&instructions)
    }
}

#[test]
fn first_action_creates_the_wallet_and_stores_the_guardians() {
    let mut scenario = Scenario::new();
    let request = scenario.request.clone();
    let relayer = scenario.relayer();
    let relayer_before = scenario.env.balance(&relayer);

    let meta = scenario.send(&request);

    let wallet = scenario
        .env
        .wallet(&request.wallet_id)
        .expect("first action creates the state PDA");
    assert_eq!(wallet.active_key, scenario.key.compressed_pubkey());
    assert_eq!(wallet.nonce, 1);
    assert_eq!(wallet.guardians, request.guardians);
    assert_eq!(
        wallet.guardians[0],
        Guardian::P256(scenario.guardian.compressed_pubkey())
    );
    assert!(wallet.rotation.is_none());

    // Only the refund leaves the vault.
    assert_eq!(
        scenario.env.balance(&vault_pda(&request.wallet_id)),
        VAULT_FUNDING - RELAYER_FEE
    );
    let rent = scenario.env.balance(&wallet_pda(&request.wallet_id));
    assert_eq!(
        scenario.env.balance(&relayer),
        relayer_before - meta.fee - rent + RELAYER_FEE
    );
}

#[test]
fn second_call_replaces_the_whole_list() {
    let mut scenario = Scenario::new();
    let first = scenario.request.clone();
    scenario.send(&first);

    let other = EnclaveKey::from_seed([10u8; 32]);
    let second = SetGuardiansRequest {
        nonce: 1,
        guardians: [
            Guardian::None,
            Guardian::P256(other.compressed_pubkey()),
            Guardian::None,
        ],
        ..first
    };
    scenario.send(&second);

    let wallet = scenario.env.wallet(&second.wallet_id).unwrap();
    assert_eq!(wallet.nonce, 2);
    assert_eq!(wallet.guardians, second.guardians);
}

#[test]
fn rejects_a_webauthn_guardian() {
    let mut scenario = Scenario::new();
    let mut request = scenario.request.clone();
    request.guardians[1] = Guardian::WebAuthn([0x42; 33]);

    let failed = scenario.try_send(&request).unwrap_err();
    assert_program_error(&failed, EnclaveKitError::WebAuthnGuardianUnsupported);
}
