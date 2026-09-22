mod common;

use anchor_lang::{solana_program::instruction::Instruction, InstructionData, ToAccountMetas};
use common::{EnclaveKey, Env};

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

#[test]
fn program_reads_pubkey_and_message_from_the_precompile() {
    let key = EnclaveKey::from_seed([7u8; 32]);
    let message = b"hello enclave";

    let mut env = Env::new();
    let result = env.send(&[
        key.precompile_instruction(message),
        transfer_sol_instruction(),
    ]);

    let meta = result.unwrap_or_else(|failed|
        panic!("{:?}\n{:#?}", failed.err, failed.meta.logs)
    );
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
