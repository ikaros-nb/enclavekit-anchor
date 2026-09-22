use anchor_lang::prelude::*;

// PDA seeds

#[constant]
pub const WALLET_SEED: &[u8] = b"wallet";

#[constant]
pub const VAULT_SEED: &[u8] = b"vault";

// Keys and signatures

/// Compressed SEC1 P-256 public key.
pub const COMPRESSED_PUBKEY_LEN: usize = 33;

// Guardians and rotation

/// Fixed slot count; each slot costs 1 + 33 bytes of rent.
pub const MAX_GUARDIANS: usize = 3;
