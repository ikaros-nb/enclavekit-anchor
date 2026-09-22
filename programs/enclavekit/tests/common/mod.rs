use anchor_lang::solana_program::instruction::Instruction;
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

    /// Signs `message` (ECDSA over SHA-256, low-S) and wraps it in the
    /// precompile instruction with the fixed layout the program expects.
    pub fn precompile_instruction(&self, message: &[u8]) -> Instruction {
        let signature: Signature = self.0.sign(message);
        let sig_bytes: [u8; 64] = signature.normalize_s().to_bytes().into();
        new_secp256r1_instruction_with_signature(message, &sig_bytes, &self.compressed_pubkey())
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
}
