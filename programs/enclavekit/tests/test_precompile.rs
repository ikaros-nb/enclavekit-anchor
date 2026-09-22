mod common;

use anchor_lang::{
    solana_program::{instruction::Instruction, system_instruction},
    InstructionData, ToAccountMetas,
};
use common::{EnclaveKey, Env};
use enclavekit::{constants::SECP256R1_MESSAGE_OFFSET, error::EnclaveKitError};
use litesvm::types::FailedTransactionMetadata;
use solana_precompile_error::PrecompileError;
use solana_signer::Signer;

fn transfer_sol_instruction() -> Instruction {
    Instruction::new_with_bytes(
        enclavekit::id(),
        &enclavekit::instruction::TransferSol {}.data(),
        enclavekit::accounts::TransferSol {
            instructions_sysvar: solana_instructions_sysvar::ID,
        }
        .to_account_metas(None),
    )
}

fn assert_failed_at(failed: &FailedTransactionMetadata, index: u8, expected: &str) {
    let actual = format!("{:?}", failed.err);
    let prefix = format!("InstructionError({index}, ");
    assert!(
        actual.starts_with(&prefix) && actual.contains(expected),
        "expected failure at instruction {index} with {expected}, got {actual}\n{:#?}",
        failed.meta.logs
    );
}

#[test]
fn program_reads_pubkey_and_message_from_the_precompile() {
    let key = EnclaveKey::from_seed([7u8; 32]);
    let message = b"hello enclave";

    let mut env = Env::new();
    let result = env.send(&[
        key.precompile_instruction(message),
        transfer_sol_instruction(),
    ]);

    let meta = result.unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs));
    let expected = format!(
        "pubkey[0]={} message_len={}",
        key.compressed_pubkey()[0],
        message.len()
    );
    assert!(
        meta.logs.iter().any(|log| log.contains(&expected)),
        "expected a log containing {expected:?}, got {:#?}",
        meta.logs
    );
}

#[test]
fn fails_when_there_is_no_instruction_before() {
    // transfer_sol at index 0: `current - 1` is negative, the sysvar helper
    // refuses with InvalidArgument before our own checks even run.
    let mut env = Env::new();
    let failed = env.send(&[
        transfer_sol_instruction()
    ]).unwrap_err();
    assert_failed_at(&failed, 0, "InvalidArgument");
}

#[test]
fn fails_when_the_instruction_before_is_not_the_precompile() {
    let mut env = Env::new();
    let payer = env.payer.pubkey();
    let failed = env.send(&[
        system_instruction::transfer(&payer, &payer, 1),
        transfer_sol_instruction(),
    ]).unwrap_err();

    let code = u32::from(EnclaveKitError::PrecompileProgramMismatch);
    assert_failed_at(&failed, 1, &format!("Custom({code})"));
}

#[test]
fn runtime_rejects_a_tampered_message_before_the_program_runs() {
    let key = EnclaveKey::from_seed([7u8; 32]);
    let mut precompile = key.precompile_instruction(b"hello enclave");
    // flip one bit of the first message byte: the signature no longer matches
    precompile.data[SECP256R1_MESSAGE_OFFSET] ^= 1;

    let mut env = Env::new();
    let failed = env
        .send(&[precompile, transfer_sol_instruction()])
        .unwrap_err();

    let code = PrecompileError::InvalidSignature as u32;
    assert_failed_at(&failed, 0, &format!("Custom({code})"));
    assert!(
        !failed.meta.logs.iter().any(|log| log.contains("pubkey[0]=")),
        "the program must not have run: {:#?}",
        failed.meta.logs
    );
}
