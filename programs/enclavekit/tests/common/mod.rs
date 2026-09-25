// Compiled once per test file: helpers a file does not use look dead there.
#![allow(dead_code)]

mod requests;
pub use requests::*;

use anchor_lang::prelude::{Clock, Pubkey};
use anchor_lang::solana_program::instruction::error::InstructionError;
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::AccountDeserialize;
use enclavekit::{error::EnclaveKitError, state::SmartWallet};
use litesvm::{types::FailedTransactionMetadata, LiteSVM};
use solana_keypair::Keypair;
use solana_message::{Message, VersionedMessage};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_error::TransactionError;

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

    /// Moves the Clock sysvar forward: the program reads its time from it.
    pub fn warp(&mut self, seconds: i64) {
        let mut clock = self.svm.get_sysvar::<Clock>();
        clock.unix_timestamp += seconds;
        self.svm.set_sysvar(&clock);
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
