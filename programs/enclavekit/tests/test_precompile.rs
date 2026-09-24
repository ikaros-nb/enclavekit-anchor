mod common;

use anchor_lang::{
    prelude::Pubkey,
    solana_program::{instruction::Instruction, system_instruction},
};
use common::{assert_failed_at, assert_program_error, EnclaveKey, Env, TransferSolRequest};
use enclavekit::{constants::SECP256R1_MESSAGE_OFFSET, error::EnclaveKitError};
use solana_precompile_error::PrecompileError;
use solana_signer::Signer;

/// Any `transfer_sol` instruction will do: these tests fail before the
/// program looks at its arguments.
fn transfer_sol_instruction(relayer: &Pubkey) -> Instruction {
    TransferSolRequest {
        wallet_id: [0u8; 32],
        to: *relayer,
        lamports: 0,
        nonce: 0,
        expires_at: i64::MAX,
        max_relayer_fee: 0,
        relayer_fee: 0,
    }
    .instruction(relayer)
}

#[test]
fn fails_when_there_is_no_instruction_before() {
    // transfer_sol at index 0: `current - 1` is negative, the sysvar helper
    // refuses with InvalidArgument before our own checks even run.
    let mut env = Env::new();
    let relayer = env.payer.pubkey();
    let failed = env.send(&[
        transfer_sol_instruction(&relayer)
    ]).unwrap_err();
    assert_failed_at(&failed, 0, "InvalidArgument");
}

#[test]
fn fails_when_the_instruction_before_is_not_the_precompile() {
    let mut env = Env::new();
    let payer = env.payer.pubkey();
    let failed = env.send(&[
        system_instruction::transfer(&payer, &payer, 1),
        transfer_sol_instruction(&payer),
    ]).unwrap_err();

    assert_program_error(&failed, EnclaveKitError::PrecompileProgramMismatch);
}

#[test]
fn runtime_rejects_a_tampered_message_before_the_program_runs() {
    let key = EnclaveKey::from_seed([7u8; 32]);
    let mut precompile = key.precompile_instruction(b"hello enclave");
    // flip one bit of the first message byte: the signature no longer matches
    precompile.data[SECP256R1_MESSAGE_OFFSET] ^= 1;

    let mut env = Env::new();
    let relayer = env.payer.pubkey();
    let failed = env
        .send(&[precompile, transfer_sol_instruction(&relayer)])
        .unwrap_err();

    let code = PrecompileError::InvalidSignature as u32;
    assert_failed_at(&failed, 0, &format!("Custom({code})"));
}
