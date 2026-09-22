use anchor_lang::prelude::*;

// PDA seeds

#[constant]
pub const WALLET_SEED: &[u8] = b"wallet";

#[constant]
pub const VAULT_SEED: &[u8] = b"vault";

// Keys and signatures

/// secp256r1 precompile
/// See: `new_secp256r1_instruction_with_signature`
/// https://crates.io/crates/solana-secp256r1-program/3.0.0/code/src/lib.rs
///
/// - 0       num_signatures (u8) = 1
/// - 1       padding
/// - 2..16   Secp256r1SignatureOffsets, 7 × u16 LE
/// - 16..49  compressed pubkey
/// - 49..113 signature
/// - 113..   message
pub const SECP256R1_PROGRAM_ID: Pubkey = pubkey!("Secp256r1SigVerify1111111111111111111111111");

/// Compressed SEC1 P-256 public key.
/// - `COMPRESSED_PUBKEY_SERIALIZED_SIZE` on crate
pub const COMPRESSED_PUBKEY_LEN: usize = 33;
/// ECDSA P-256 signature, r ‖ s, low-S.
/// - `SIGNATURE_SERIALIZED_SIZE` on crate
pub const P256_SIGNATURE_LEN: usize = 64;
/// `SIGNATURE_OFFSETS_START` on crate
pub const PRECOMPILE_OFFSETS_START: usize = 2;
/// `SIGNATURE_OFFSETS_SERIALIZED_SIZE` on crate
pub const PRECOMPILE_OFFSETS_LEN: usize = 14;
/// `DATA_START` on crate
pub const PRECOMPILE_DATA_START: usize = PRECOMPILE_OFFSETS_START + PRECOMPILE_OFFSETS_LEN;
/// Each offset comes with an instruction index saying which instruction of
/// the transaction holds the bytes. `u16::MAX` means the precompile
/// instruction itself, the only value we accept.
/// 
/// See `get_data_slice`: https://github.com/anza-xyz/agave/blob/v3.1.8/precompiles/src/secp256r1.rs
/// ```text
/// let instruction = if instruction_index == u16::MAX {
/// data
/// } else {
///    instruction_datas[instruction_index]
/// };
/// ```
pub const PRECOMPILE_CURRENT_INSTRUCTION: u16 = u16::MAX;

/// offset 16
pub const SECP256R1_PUBKEY_OFFSET: usize = PRECOMPILE_DATA_START;
/// offset 49 (16 + 33)
pub const SECP256R1_SIGNATURE_OFFSET: usize = SECP256R1_PUBKEY_OFFSET + COMPRESSED_PUBKEY_LEN;
/// offset 113 (49 + 64)
pub const SECP256R1_MESSAGE_OFFSET: usize = SECP256R1_SIGNATURE_OFFSET + P256_SIGNATURE_LEN;

// Guardians and rotation

/// Fixed slot count; each slot costs 1 + 33 bytes of rent.
pub const MAX_GUARDIANS: usize = 3;
