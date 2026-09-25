// Compiled once per test file: helpers a file does not use look dead there.
#![allow(dead_code)]

use anchor_lang::prelude::{Clock, Pubkey};
use anchor_lang::solana_program::instruction::error::InstructionError;
use anchor_lang::solana_program::{instruction::Instruction, system_program};
use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use enclavekit::{
    authorization::Authorization,
    error::EnclaveKitError,
    state::{Guardian, SmartWallet},
    MAX_GUARDIANS, VAULT_SEED, WALLET_SEED,
};
use enclavekit_encoding::{action::Action, preimage::Preimage, wallet::wallet_id};
use litesvm::{types::FailedTransactionMetadata, LiteSVM};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use solana_keypair::Keypair;
use solana_message::{Message, VersionedMessage};
use solana_secp256r1_program::new_secp256r1_instruction_with_signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_error::TransactionError;

/// A P-256 key standing in for the Secure Enclave.
#[derive(Clone)]
pub struct EnclaveKey(SigningKey);

impl EnclaveKey {
    /// Deterministic key from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_slice(&seed).expect("seed is a valid P-256 scalar"))
    }

    /// Compressed SEC1 encoding: 0x02 or 0x03 followed by the 32-byte x coordinate.
    pub fn compressed_pubkey(&self) -> [u8; 33] {
        let point = self.0.verifying_key().as_affine().to_sec1_point(true);
        point
            .as_bytes()
            .try_into()
            .expect("compressed point is 33 bytes")
    }

    /// SHA-256 of the compressed key: the wallet identity the program expects
    /// on first use.
    pub fn wallet_id(&self) -> [u8; 32] {
        wallet_id(&self.compressed_pubkey())
    }

    /// Signs `message` (ECDSA over SHA-256, low-S) and wraps it in the
    /// precompile instruction with the fixed layout the program expects.
    pub fn precompile_instruction(&self, message: &[u8]) -> Instruction {
        let signature: Signature = self.0.sign(message);
        let sig_bytes: [u8; 64] = signature.normalize_s().to_bytes().into();
        new_secp256r1_instruction_with_signature(message, &sig_bytes, &self.compressed_pubkey())
    }

    /// Same signature with `s` replaced by `n - s`: still a valid ECDSA
    /// signature mathematically, but high-S, which the runtime refuses.
    pub fn precompile_instruction_high_s(&self, message: &[u8]) -> Instruction {
        let signature: Signature = self.0.sign(message);
        let (r, s) = signature.normalize_s().split_scalars();
        let high = Signature::from_scalars(r.to_bytes(), (-*s).to_bytes())
            .expect("n - s is a valid non-zero scalar");
        let sig_bytes: [u8; 64] = high.to_bytes().into();
        new_secp256r1_instruction_with_signature(message, &sig_bytes, &self.compressed_pubkey())
    }
}

pub fn wallet_pda(wallet_id: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[WALLET_SEED, wallet_id], &enclavekit::id()).0
}

pub fn vault_pda(wallet_id: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[VAULT_SEED, wallet_id], &enclavekit::id()).0
}

/// One enclave-authorised call: what the enclave signs and what the relayer
/// sends. Every instruction that goes through `verify_enclave_authorization`
/// implements it; `preimage` and `sign` come for free.
pub trait EnclaveRequest {
    /// The signed header: wallet, nonce, expiry, fee cap.
    fn authorization(&self) -> Authorization;
    /// The action the enclave signs, as the program will rebuild it.
    fn action(&self) -> Action;
    /// The program instruction alone.
    fn instruction(&self, relayer: &Pubkey) -> Instruction;

    /// The bytes the enclave signs
    fn preimage(&self) -> Vec<u8> {
        let auth = self.authorization();
        let action = self.action();
        Preimage {
            program_id: enclavekit::id().to_bytes(),
            wallet_id: auth.wallet_id,
            nonce: auth.nonce,
            expires_at: auth.expires_at,
            max_relayer_fee: auth.max_relayer_fee,
            action: &action,
        }
        .to_bytes()
    }

    /// The pair a transaction carries: precompile first, program second.
    fn sign(&self, key: &EnclaveKey, relayer: &Pubkey) -> [Instruction; 2] {
        [
            key.precompile_instruction(&self.preimage()),
            self.instruction(relayer),
        ]
    }
}

/// Everything one `transfer_sol` call needs
#[derive(Clone)]
pub struct TransferSolRequest {
    pub wallet_id: [u8; 32],
    pub to: Pubkey,
    pub lamports: u64,
    pub nonce: u64,
    pub expires_at: i64,
    pub max_relayer_fee: u64,
    /// Asked by the relayer, outside the signed bytes.
    pub relayer_fee: u64,
}

impl EnclaveRequest for TransferSolRequest {
    fn authorization(&self) -> Authorization {
        Authorization {
            wallet_id: self.wallet_id,
            nonce: self.nonce,
            expires_at: self.expires_at,
            max_relayer_fee: self.max_relayer_fee,
        }
    }

    fn action(&self) -> Action {
        Action::TransferSol {
            to: self.to.to_bytes(),
            lamports: self.lamports,
        }
    }

    fn instruction(&self, relayer: &Pubkey) -> Instruction {
        Instruction::new_with_bytes(
            enclavekit::id(),
            &enclavekit::instruction::TransferSol {
                wallet_id: self.wallet_id,
                nonce: self.nonce,
                expires_at: self.expires_at,
                max_relayer_fee: self.max_relayer_fee,
                lamports: self.lamports,
                relayer_fee: self.relayer_fee,
            }
            .data(),
            enclavekit::accounts::TransferSol {
                wallet: wallet_pda(&self.wallet_id),
                vault: vault_pda(&self.wallet_id),
                to: self.to,
                relayer: *relayer,
                instructions_sysvar: solana_instructions_sysvar::ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
        )
    }
}

/// Everything one `set_guardians` call needs
#[derive(Clone)]
pub struct SetGuardiansRequest {
    pub wallet_id: [u8; 32],
    pub guardians: [Guardian; MAX_GUARDIANS],
    pub nonce: u64,
    pub expires_at: i64,
    pub max_relayer_fee: u64,
    /// Asked by the relayer, outside the signed bytes.
    pub relayer_fee: u64,
}

impl EnclaveRequest for SetGuardiansRequest {
    fn authorization(&self) -> Authorization {
        Authorization {
            wallet_id: self.wallet_id,
            nonce: self.nonce,
            expires_at: self.expires_at,
            max_relayer_fee: self.max_relayer_fee,
        }
    }

    fn action(&self) -> Action {
        Action::SetGuardians {
            guardians: self.guardians.map(Into::into),
        }
    }

    fn instruction(&self, relayer: &Pubkey) -> Instruction {
        Instruction::new_with_bytes(
            enclavekit::id(),
            &enclavekit::instruction::SetGuardians {
                wallet_id: self.wallet_id,
                nonce: self.nonce,
                expires_at: self.expires_at,
                max_relayer_fee: self.max_relayer_fee,
                guardians: self.guardians,
                relayer_fee: self.relayer_fee,
            }
            .data(),
            enclavekit::accounts::SetGuardians {
                wallet: wallet_pda(&self.wallet_id),
                vault: vault_pda(&self.wallet_id),
                relayer: *relayer,
                instructions_sysvar: solana_instructions_sysvar::ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
        )
    }
}

/// Everything one `cancel_rotation` call needs
#[derive(Clone)]
pub struct CancelRotationRequest {
    pub wallet_id: [u8; 32],
    pub nonce: u64,
    pub expires_at: i64,
    pub max_relayer_fee: u64,
    /// Asked by the relayer, outside the signed bytes.
    pub relayer_fee: u64,
}

impl EnclaveRequest for CancelRotationRequest {
    fn authorization(&self) -> Authorization {
        Authorization {
            wallet_id: self.wallet_id,
            nonce: self.nonce,
            expires_at: self.expires_at,
            max_relayer_fee: self.max_relayer_fee,
        }
    }

    fn action(&self) -> Action {
        Action::CancelRotation
    }

    fn instruction(&self, relayer: &Pubkey) -> Instruction {
        Instruction::new_with_bytes(
            enclavekit::id(),
            &enclavekit::instruction::CancelRotation {
                wallet_id: self.wallet_id,
                nonce: self.nonce,
                expires_at: self.expires_at,
                max_relayer_fee: self.max_relayer_fee,
                relayer_fee: self.relayer_fee,
            }
            .data(),
            enclavekit::accounts::CancelRotation {
                wallet: wallet_pda(&self.wallet_id),
                vault: vault_pda(&self.wallet_id),
                relayer: *relayer,
                instructions_sysvar: solana_instructions_sysvar::ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
        )
    }
}

/// Everything one `propose_rotation` call needs
#[derive(Clone)]
pub struct ProposeRotationRequest {
    pub wallet_id: [u8; 32],
    pub new_key: [u8; 33],
    pub nonce: u64,
    pub expires_at: i64,
    pub max_relayer_fee: u64,
    /// Asked by the relayer, outside the signed bytes.
    pub relayer_fee: u64,
}

impl EnclaveRequest for ProposeRotationRequest {
    fn authorization(&self) -> Authorization {
        Authorization {
            wallet_id: self.wallet_id,
            nonce: self.nonce,
            expires_at: self.expires_at,
            max_relayer_fee: self.max_relayer_fee,
        }
    }

    fn action(&self) -> Action {
        Action::ProposeRotation {
            new_key: self.new_key,
        }
    }

    fn instruction(&self, relayer: &Pubkey) -> Instruction {
        Instruction::new_with_bytes(
            enclavekit::id(),
            &enclavekit::instruction::ProposeRotation {
                wallet_id: self.wallet_id,
                nonce: self.nonce,
                expires_at: self.expires_at,
                max_relayer_fee: self.max_relayer_fee,
                new_key: self.new_key,
                relayer_fee: self.relayer_fee,
            }
            .data(),
            enclavekit::accounts::ProposeRotation {
                wallet: wallet_pda(&self.wallet_id),
                vault: vault_pda(&self.wallet_id),
                relayer: *relayer,
                instructions_sysvar: solana_instructions_sysvar::ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
        )
    }
}

pub struct Env {
    pub svm: LiteSVM,
    pub payer: Keypair,
}

impl Env {
    pub fn new() -> Self {
        let mut svm = LiteSVM::new();
        let bytes = include_bytes!(concat!(
            env!("CARGO_TARGET_TMPDIR"),
            "/../deploy/enclavekit.so"
        ));
        svm.add_program(enclavekit::id(), bytes).unwrap();

        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();

        Self { svm, payer }
    }

    pub fn send(
        &mut self,
        instructions: &[Instruction],
    ) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata>
    {
        // A fresh blockhash makes every send a distinct transaction.
        self.svm.expire_blockhash();
        let blockhash = self.svm.latest_blockhash();
        let message =
            Message::new_with_blockhash(instructions, Some(&self.payer.pubkey()), &blockhash);
        let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(message), &[&self.payer])
            .unwrap();
        self.svm.send_transaction(tx)
    }

    pub fn balance(&self, address: &Pubkey) -> u64 {
        self.svm.get_balance(address).unwrap_or(0)
    }

    pub fn wallet(&self, wallet_id: &[u8; 32]) -> Option<SmartWallet> {
        let account = self.svm.get_account(&wallet_pda(wallet_id))?;
        let wallet = SmartWallet::try_deserialize(&mut account.data.as_slice())
            .expect("state PDA holds a SmartWallet");
        Some(wallet)
    }

    pub fn unix_timestamp(&self) -> i64 {
        self.svm.get_sysvar::<Clock>().unix_timestamp
    }
}

/// Index of `transfer_sol` in the transactions the tests build: precompile
/// first, program second.
pub const PROGRAM_INDEX: u8 = 1;

/// Loose check on the Debug output, for errors raised by the runtime or by
/// another program (`InvalidArgument`, `Custom(1)` from System, ...).
pub fn assert_failed_at(failed: &FailedTransactionMetadata, index: u8, expected: &str) {
    let actual = format!("{:?}", failed.err);
    let prefix = format!("InstructionError({index}, ");
    assert!(
        actual.starts_with(&prefix) && actual.contains(expected),
        "expected failure at instruction {index} with {expected}, got {actual}\n{:#?}",
        failed.meta.logs
    );
}

/// Exact check: `transfer_sol` refused with this EnclaveKit error.
pub fn assert_program_error(failed: &FailedTransactionMetadata, expected: EnclaveKitError) {
    assert_program_error_at(failed, PROGRAM_INDEX, expected);
}

/// Same, for transactions where `transfer_sol` is not at `PROGRAM_INDEX`.
pub fn assert_program_error_at(
    failed: &FailedTransactionMetadata,
    index: u8,
    expected: EnclaveKitError,
) {
    let expected_err =
        TransactionError::InstructionError(index, InstructionError::Custom(expected.into()));
    assert_eq!(
        failed.err, expected_err,
        "expected {expected:?}\n{:#?}",
        failed.meta.logs
    );
}
