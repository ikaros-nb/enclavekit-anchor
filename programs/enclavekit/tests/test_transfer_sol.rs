mod common;

use anchor_lang::prelude::Pubkey;
use anchor_lang::solana_program::instruction::Instruction;
use common::{assert_program_error, vault_pda, wallet_pda, EnclaveKey, Env, TransferSolRequest};
use enclavekit::error::EnclaveKitError;
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use solana_signer::Signer;

const VAULT_FUNDING: u64 = 1_000_000_000;
const LAMPORTS: u64 = 100_000_000;
const MAX_RELAYER_FEE: u64 = 100_000;
const RELAYER_FEE: u64 = 50_000;

struct Scenario {
    env: Env,
    key: EnclaveKey,
    request: TransferSolRequest,
}

impl Scenario {
    fn new() -> Self {
        let mut env = Env::new();
        let key = EnclaveKey::from_seed([7u8; 32]);
        let wallet_id = key.wallet_id();
        env.svm.airdrop(&vault_pda(&wallet_id), VAULT_FUNDING).unwrap();

        let request = TransferSolRequest {
            wallet_id,
            to: Pubkey::new_unique(),
            lamports: LAMPORTS,
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

    /// Happy-path send: panics with the logs if the transaction fails.
    fn send(&mut self, request: &TransferSolRequest) -> TransactionMetadata {
        self.try_send(request)
            .unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs))
    }
    
    /// Signs with the scenario key and sends; the caller decides what a
    /// failure means.
    fn try_send(
        &mut self,
        request: &TransferSolRequest,
    ) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        let instructions = request.sign(&self.key, &self.relayer());
        self.try_send_raw(&instructions)
    }

    /// For transactions whose precompile and program instructions do not come
    /// from the same request (tampered preimage, other key, ...).
    fn try_send_raw(
        &mut self,
        instructions: &[Instruction],
    ) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        self.env.send(instructions)
    }
}

#[test]
fn first_action_creates_the_wallet_pays_and_refunds() {
    let mut scenario = Scenario::new();
    let request = scenario.request.clone();
    let relayer = scenario.relayer();
    let relayer_before = scenario.env.balance(&relayer);

    let meta = scenario.send(&request);

    let wallet = scenario
        .env
        .wallet(&request.wallet_id)
        .expect("first action creates the state PDA");
    assert_eq!(wallet.wallet_id, request.wallet_id);
    assert_eq!(wallet.active_key, scenario.key.compressed_pubkey());
    assert_eq!(wallet.nonce, 1);
    assert!(!wallet.attested);
    assert!(wallet.rotation.is_none());

    assert_eq!(scenario.env.balance(&request.to), LAMPORTS);
    assert_eq!(
        scenario.env.balance(&vault_pda(&request.wallet_id)),
        VAULT_FUNDING - LAMPORTS - RELAYER_FEE
    );

    // The relayer paid the transaction fee and the state rent, then got its
    // requested fee back from the vault.
    let rent = scenario.env.balance(&wallet_pda(&request.wallet_id));
    assert_eq!(
        scenario.env.balance(&relayer),
        relayer_before - meta.fee - rent + RELAYER_FEE
    );
}

#[test]
fn second_action_uses_the_next_nonce() {
    let mut scenario = Scenario::new();
    let first = scenario.request.clone();
    scenario.send(&first);

    let second = TransferSolRequest { nonce: 1, ..first.clone() };
    scenario.send(&second);

    let wallet = scenario.env.wallet(&first.wallet_id).unwrap();
    assert_eq!(wallet.nonce, 2);
    assert_eq!(scenario.env.balance(&first.to), 2 * LAMPORTS);
    assert_eq!(
        scenario.env.balance(&vault_pda(&first.wallet_id)),
        VAULT_FUNDING - 2 * (LAMPORTS + RELAYER_FEE)
    );
}

// Negative paths: each one clones the valid request and changes one thing.

#[test]
fn rejects_a_replayed_nonce() {
    todo!("first send, then the same request again: NonceMismatch")
}

#[test]
fn rejects_a_nonce_ahead_of_the_counter() {
    todo!("first send, then nonce 2: NonceMismatch")
}

#[test]
fn rejects_an_expired_authorization() {
    todo!("expires_at in the past: AuthorizationExpired")
}

#[test]
fn rejects_another_key_on_first_use() {
    todo!("sign with another P-256 key, same wallet_id: WalletIdMismatch")
}

#[test]
fn rejects_another_key_once_the_wallet_exists() {
    todo!("first send, then sign with another key: KeyMismatch")
}

#[test]
fn caps_the_refund_at_max_relayer_fee() {
    todo!("relayer_fee above the cap: vault only loses LAMPORTS + MAX_RELAYER_FEE")
}
