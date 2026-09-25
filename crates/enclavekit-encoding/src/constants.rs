//! Values the program and the Swift SDK must agree on byte for byte.
//! Defined once here; the program re-exports them.

/// Seed of the state PDA: `[WALLET_SEED, wallet_id]`.
pub const WALLET_SEED: &[u8] = b"wallet";
/// Seed of the vault PDA: `[VAULT_SEED, wallet_id]`.
pub const VAULT_SEED: &[u8] = b"vault";

/// Compressed SEC1 P-256 public key: 0x02 or 0x03 then the x coordinate.
/// - `COMPRESSED_PUBKEY_SERIALIZED_SIZE` on crate
pub const COMPRESSED_PUBKEY_LEN: usize = 33;

/// Fixed guardian slot count in `SmartWallet` and in `Action::SetGuardians`.
pub const MAX_GUARDIANS: usize = 3;
