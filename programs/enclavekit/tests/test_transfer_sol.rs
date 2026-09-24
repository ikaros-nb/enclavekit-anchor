mod common;

use anchor_lang::error::ErrorCode;
use anchor_lang::prelude::Pubkey;
use anchor_lang::solana_program::instruction::Instruction;
use common::{
    assert_failed_at, assert_program_error, vault_pda, wallet_pda, EnclaveKey, Env,
    TransferSolRequest, PROGRAM_INDEX,
};
use enclavekit::error::EnclaveKitError;
use enclavekit_encoding::preimage::PROGRAM_ID_OFFSET;
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use solana_signer::Signer;
use solana_system_interface::error::SystemError;
use solana_transaction_error::TransactionError;

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
        Self::with_vault(VAULT_FUNDING)
    }

    /// Same scenario with a chosen vault balance
    fn with_vault(funding: u64) -> Self {
        let mut env = Env::new();
        let key = EnclaveKey::from_seed([7u8; 32]);
        let wallet_id = key.wallet_id();
        env.svm.airdrop(&vault_pda(&wallet_id), funding).unwrap();

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

    /// Signs `preimage` as is, but sends the program instruction built from
    /// `request`: the two disagree whenever `preimage` was tampered with.
    fn try_send_with_preimage(
        &mut self,
        preimage: &[u8],
        request: &TransferSolRequest,
    ) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        let instructions = [
            self.key.precompile_instruction(preimage),
            request.instruction(&self.relayer()),
        ];
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
    let mut scenario = Scenario::new();
    let first = scenario.request.clone();
    scenario.send(&first);
    let failed = scenario
        .try_send(&first)
        .unwrap_err();
    assert_program_error(&failed, EnclaveKitError::NonceMismatch);
}

#[test]
fn rejects_a_nonce_ahead_of_the_counter() {
    let mut scenario = Scenario::new();
    let first = scenario.request.clone();
    scenario.send(&first);

    let second = TransferSolRequest { nonce: 2, ..first.clone() };
    let failed = scenario
        .try_send(&second)
        .unwrap_err();
    assert_program_error(&failed, EnclaveKitError::NonceMismatch);
}

#[test]
fn rejects_an_expired_authorization() {
    let mut scenario = Scenario::new();
    let tampered_request = TransferSolRequest {
        expires_at: scenario.env.unix_timestamp() - 1,
        ..scenario.request.clone()
    };

    let failed = scenario
        .try_send(&tampered_request)
        .unwrap_err();
    assert_program_error(&failed, EnclaveKitError::AuthorizationExpired);
}

#[test]
fn rejects_another_key_on_first_use() {
    let mut scenario = Scenario::new();
    let other_key = EnclaveKey::from_seed([8u8; 32]);
    let instructions = scenario.request.sign(&other_key, &scenario.relayer());

    let failed = scenario.try_send_raw(&instructions).unwrap_err();
    assert_program_error(&failed, EnclaveKitError::WalletIdMismatch);
}

#[test]
fn rejects_another_key_once_the_wallet_exists() {
    let mut scenario = Scenario::new();
    let first = scenario.request.clone();
    scenario.send(&first);

    let other_key = EnclaveKey::from_seed([8u8; 32]);
    let second = TransferSolRequest { nonce: 1, ..first };
    let instructions = second.sign(&other_key, &scenario.relayer());

    let failed = scenario.try_send_raw(&instructions).unwrap_err();
    assert_program_error(&failed, EnclaveKitError::KeyMismatch);
}

#[test]
fn caps_the_refund_at_max_relayer_fee() {
    let mut scenario = Scenario::new();
    let greedy_relayer_request = TransferSolRequest {
        relayer_fee: 2 * MAX_RELAYER_FEE,
        ..scenario.request.clone()
    };
    let relayer = scenario.relayer();
    let relayer_before = scenario.env.balance(&relayer);

    let meta = scenario.send(&greedy_relayer_request);

    assert_eq!(
        scenario.env.balance(&vault_pda(&greedy_relayer_request.wallet_id)),
        VAULT_FUNDING - LAMPORTS - MAX_RELAYER_FEE
    );
    // The relayer asked for twice the cap and only got the cap back
    let rent = scenario.env.balance(&wallet_pda(&greedy_relayer_request.wallet_id));
    assert_eq!(
        scenario.env.balance(&relayer),
        relayer_before - meta.fee - rent + MAX_RELAYER_FEE
    );
}

// Tampered preimages: the signature is valid for the bytes it covers, so the
// runtime accepts it. Only the program can notice the bytes do not describe
// the instruction it is executing.

#[test]
fn rejects_a_signature_over_another_amount() {
    let mut scenario = Scenario::new();
    let request = scenario.request.clone();
    let signed = TransferSolRequest { lamports: LAMPORTS + 1, ..request.clone() }.preimage();

    let failed = scenario.try_send_with_preimage(&signed, &request).unwrap_err();
    assert_program_error(&failed, EnclaveKitError::PreimageMismatch);
}

#[test]
fn rejects_a_signature_over_another_recipient() {
    let mut scenario = Scenario::new();
    let request = scenario.request.clone();
    let signed = TransferSolRequest { to: Pubkey::new_unique(), ..request.clone() }.preimage();

    let failed = scenario.try_send_with_preimage(&signed, &request).unwrap_err();
    assert_program_error(&failed, EnclaveKitError::PreimageMismatch);
}

#[test]
fn rejects_a_signature_over_another_domain_tag() {
    let mut scenario = Scenario::new();
    let request = scenario.request.clone();
    let mut signed = request.preimage();
    signed[0] ^= 1;

    let failed = scenario.try_send_with_preimage(&signed, &request).unwrap_err();
    assert_program_error(&failed, EnclaveKitError::PreimageMismatch);
}

#[test]
fn rejects_a_signature_over_another_program_id() {
    let mut scenario = Scenario::new();
    let request = scenario.request.clone();
    let mut signed = request.preimage();
    signed[PROGRAM_ID_OFFSET] ^= 1;

    let failed = scenario.try_send_with_preimage(&signed, &request).unwrap_err();
    assert_program_error(&failed, EnclaveKitError::PreimageMismatch);
}

// Failures raised by Anchor

#[test]
fn rejects_a_refund_account_that_did_not_sign() {
    // Second action on purpose: on the first one `init_if_needed` would CPI
    // into System with the relayer as payer and the runtime would refuse
    // with PrivilegeEscalation before Anchor's Signer check is reached.
    let mut scenario = Scenario::new();
    let first = scenario.request.clone();
    scenario.send(&first);

    // A stranger claims the refund without signing. It must differ from the
    // fee payer: the same key in both roles would be merged back into a signer.
    let stranger = Pubkey::new_unique();
    let second = TransferSolRequest { nonce: 1, ..first };
    let mut instructions = second.sign(&scenario.key, &stranger);
    instructions[PROGRAM_INDEX as usize]
        .accounts
        .iter_mut()
        .find(|meta| meta.pubkey == stranger)
        .expect("the relayer is one of the accounts")
        .is_signer = false;

    let failed = scenario.try_send_raw(&instructions).unwrap_err();
    let code = ErrorCode::AccountNotSigner as u32;
    assert_failed_at(&failed, PROGRAM_INDEX, &format!("Custom({code})"));
}

#[test]
fn rejects_when_the_vault_cannot_cover_the_amount() {
    let mut scenario = Scenario::with_vault(LAMPORTS - 1);
    let request = scenario.request.clone();

    let failed = scenario.try_send(&request).unwrap_err();
    // The first CPI fails inside System; its error surfaces as ours.
    let code = SystemError::ResultWithNegativeLamports as u32;
    assert_failed_at(&failed, PROGRAM_INDEX, &format!("Custom({code})"));
}

#[test]
fn rejects_when_the_vault_would_be_left_below_rent() {
    // Both CPIs succeed and leave 1 lamport in the vault. A system account
    // must hold the rent-exempt minimum or exactly 0, so the runtime rejects
    // the whole transaction at the end, without any InstructionError.
    let mut scenario = Scenario::with_vault(LAMPORTS + RELAYER_FEE + 1);
    let request = scenario.request.clone();

    let failed = scenario.try_send(&request).unwrap_err();
    assert!(
        matches!(failed.err, TransactionError::InsufficientFundsForRent { .. }),
        "expected InsufficientFundsForRent, got {:?}\n{:#?}",
        failed.err,
        failed.meta.logs
    );
}
