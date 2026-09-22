use anchor_lang::prelude::*;
use solana_instructions_sysvar::get_instruction_relative;

use crate::constants::{
    COMPRESSED_PUBKEY_LEN, PRECOMPILE_CURRENT_INSTRUCTION, PRECOMPILE_OFFSETS_START,
    SECP256R1_MESSAGE_OFFSET, SECP256R1_PROGRAM_ID, SECP256R1_PUBKEY_OFFSET,
    SECP256R1_SIGNATURE_OFFSET,
};
use crate::error::EnclaveKitError;

pub struct SignedPayload {
    pub pubkey: [u8; COMPRESSED_PUBKEY_LEN],
    pub message: Vec<u8>,
}

/// The seven `u16` fields at bytes 2..16 of the precompile data, in order.
/// - `Secp256r1SignatureOffsets` on crate
struct SignatureOffsets {
    signature_offset: u16,
    signature_instruction_index: u16,
    public_key_offset: u16,
    public_key_instruction_index: u16,
    message_data_offset: u16,
    message_data_size: u16,
    message_instruction_index: u16,
}

impl SignatureOffsets {
    fn parse(data: &[u8]) -> Self {
        let field = |i: usize| {
            let at = PRECOMPILE_OFFSETS_START + 2 * i;
            u16::from_le_bytes([data[at], data[at + 1]])
        };
        Self {
            signature_offset: field(0),
            signature_instruction_index: field(1),
            public_key_offset: field(2),
            public_key_instruction_index: field(3),
            message_data_offset: field(4),
            message_data_size: field(5),
            message_instruction_index: field(6),
        }
    }
}

/// Reads the secp256r1 precompile instruction placed just before this one.
///
/// Steps, each failing with its own error:
/// 1. load the instruction at `current_index - 1` from the Instructions sysvar;
/// 2. require the secp256r1 program id and no accounts;
/// 3. require at least `SECP256R1_MESSAGE_OFFSET` bytes and exactly one signature;
/// 4. require the seven offsets to match the fixed layout (16 / 49 / 113) and
///    every instruction index to be `u16::MAX`, i.e. "in this instruction";
/// 5. require the message to end exactly where the data ends.
///
/// Returns the compressed public key and the raw message. The signature is
/// not returned: the runtime already verified it, the program never needs it.
pub fn load_secp256r1_payload(instructions_sysvar: &AccountInfo) -> Result<SignedPayload> {
    let ix = get_instruction_relative(-1, instructions_sysvar)?;

    require_keys_eq!(
        ix.program_id,
        SECP256R1_PROGRAM_ID,
        EnclaveKitError::PrecompileProgramMismatch
    );
    require!(
        ix.accounts.is_empty(),
        EnclaveKitError::PrecompileUnexpectedAccounts
    );

    let data = &ix.data;
    require!(
        data.len() >= SECP256R1_MESSAGE_OFFSET,
        EnclaveKitError::PrecompileDataTooShort
    );
    require!(data[0] == 1, EnclaveKitError::PrecompileSignatureCountMismatch);

    let offsets = SignatureOffsets::parse(data);
    require!(
        offsets.signature_offset as usize == SECP256R1_SIGNATURE_OFFSET
            && offsets.public_key_offset as usize == SECP256R1_PUBKEY_OFFSET
            && offsets.message_data_offset as usize == SECP256R1_MESSAGE_OFFSET
            && offsets.signature_instruction_index == PRECOMPILE_CURRENT_INSTRUCTION
            && offsets.public_key_instruction_index == PRECOMPILE_CURRENT_INSTRUCTION
            && offsets.message_instruction_index == PRECOMPILE_CURRENT_INSTRUCTION,
        EnclaveKitError::PrecompileLayoutMismatch
    );
    require!(
        SECP256R1_MESSAGE_OFFSET + offsets.message_data_size as usize == data.len(),
        EnclaveKitError::PrecompileMessageSizeMismatch
    );

    let mut pubkey = [0u8; COMPRESSED_PUBKEY_LEN];
    pubkey.copy_from_slice(&data[SECP256R1_PUBKEY_OFFSET..SECP256R1_SIGNATURE_OFFSET]);

    Ok(SignedPayload {
        pubkey,
        message: data[SECP256R1_MESSAGE_OFFSET..].to_vec(),
    })
}
