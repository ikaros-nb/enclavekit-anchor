// Compiled once per test file: helpers a file does not use look dead there.
#![allow(dead_code)]

use anchor_lang::prelude::{Clock, Pubkey};
use anchor_lang::solana_program::{instruction::Instruction, system_program};
use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use enclavekit::{state::SmartWallet, VAULT_SEED, WALLET_SEED};
use enclavekit_encoding::{action::Action, preimage::Preimage, wallet::wallet_id};
use litesvm::LiteSVM;
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use solana_keypair::Keypair;
use solana_message::{Message, VersionedMessage};
use solana_secp256r1_program::new_secp256r1_instruction_with_signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

/// A P-256 key standing in for the Secure Enclave.
pub struct EnclaveKey(SigningKey);

impl EnclaveKey {
    /// Deterministic key from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_slice(&seed).expect("seed is a valid P-256 scalar"))
    }

    /// Compressed SEC1 encoding: 0x02 or 0x03 followed by the 32-byte x coordinate.
    pub fn compressed_pubkey(&self) -> [u8; 33] {
        let point = self.0.verifying_key().as_affine().to_sec1_point(true);
        point.as_bytes().try_into().expect("compressed point is 33 bytes")
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
}

pub fn wallet_pda(wallet_id: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[WALLET_SEED, wallet_id], &enclavekit::id()).0
}

pub fn vault_pda(wallet_id: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[VAULT_SEED, wallet_id], &enclavekit::id()).0
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

impl TransferSolRequest {
    /// The bytes the enclave signs
    pub fn preimage(&self) -> Vec<u8> {
        let action = Action::TransferSol {
            to: self.to.to_bytes(),
            lamports: self.lamports,
        };
        Preimage {
            program_id: enclavekit::id().to_bytes(),
            wallet_id: self.wallet_id,
            nonce: self.nonce,
            expires_at: self.expires_at,
            max_relayer_fee: self.max_relayer_fee,
            action: &action,
        }
        .to_bytes()
    }

    /// transfer_sol instruction alone
    pub fn instruction(&self, relayer: &Pubkey) -> Instruction {
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

    /// The pair a transaction carries: precompile first, `transfer_sol` second.
    pub fn sign(&self, key: &EnclaveKey, relayer: &Pubkey) -> [Instruction; 2] {
        [
            key.precompile_instruction(&self.preimage()),
            self.instruction(relayer),
        ]
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
    ) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata> {
        let blockhash = self.svm.latest_blockhash();
        let message = Message::new_with_blockhash(
            instructions, 
            Some(&self.payer.pubkey()), 
            &blockhash
        );
        let tx = VersionedTransaction::try_new(
            VersionedMessage::Legacy(message),
            &[&self.payer]
        ).unwrap();
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
