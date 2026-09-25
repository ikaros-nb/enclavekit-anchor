mod common;

use anchor_lang::{
    prelude::Pubkey,
    solana_program::{instruction::Instruction, system_instruction},
};
use common::{
    assert_failed_at, assert_program_error, assert_program_error_at, EnclaveKey, Env,
    TransferSolRequest,
};
use enclavekit::{
    constants::{PRECOMPILE_OFFSETS_START, SECP256R1_MESSAGE_OFFSET},
    error::EnclaveKitError,
};
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
    let failed = env.send(&[transfer_sol_instruction(&relayer)]).unwrap_err();
    assert_failed_at(&failed, 0, "InvalidArgument");
}

#[test]
fn fails_when_the_instruction_before_is_not_the_precompile() {
    let mut env = Env::new();
    let payer = env.payer.pubkey();
    let failed = env
        .send(&[
            system_instruction::transfer(&payer, &payer, 1),
            transfer_sol_instruction(&payer),
        ])
        .unwrap_err();

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

#[test]
fn fails_when_the_precompile_is_not_right_before() {
    // A valid precompile two slots earlier does not count: the program only
    // reads `current - 1`.
    let key = EnclaveKey::from_seed([7u8; 32]);
    let mut env = Env::new();
    let payer = env.payer.pubkey();
    let failed = env
        .send(&[
            key.precompile_instruction(b"hello enclave"),
            system_instruction::transfer(&payer, &payer, 1),
            transfer_sol_instruction(&payer),
        ])
        .unwrap_err();

    assert_program_error_at(&failed, 2, EnclaveKitError::PrecompileProgramMismatch);
}

#[test]
fn rejects_offsets_pointing_at_another_instruction() {
    let key = EnclaveKey::from_seed([7u8; 32]);
    let mut precompile = key.precompile_instruction(b"hello enclave");
    // `message_instruction_index` is the seventh u16 of the offsets block.
    // Pointing it at instruction 0, i.e. this very instruction, keeps the
    // runtime happy: it reads the same bytes. The program must still refuse,
    // it only trusts data that lives in the precompile instruction itself.
    let at = PRECOMPILE_OFFSETS_START + 2 * 6;
    precompile.data[at..at + 2].copy_from_slice(&0u16.to_le_bytes());

    let mut env = Env::new();
    let relayer = env.payer.pubkey();
    let failed = env
        .send(&[precompile, transfer_sol_instruction(&relayer)])
        .unwrap_err();

    assert_program_error(&failed, EnclaveKitError::PrecompileLayoutMismatch);
}

#[test]
fn runtime_rejects_a_high_s_signature() {
    let key = EnclaveKey::from_seed([7u8; 32]);
    let precompile = key.precompile_instruction_high_s(b"hello enclave");

    let mut env = Env::new();
    let relayer = env.payer.pubkey();
    let failed = env
        .send(&[precompile, transfer_sol_instruction(&relayer)])
        .unwrap_err();

    let code = PrecompileError::InvalidSignature as u32;
    assert_failed_at(&failed, 0, &format!("Custom({code})"));
}
