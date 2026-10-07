//! Where each field of the wallet's state account sits, for
//! `getProgramAccounts` filters: a device finds the wallets that name its
//! key without knowing their ID.
//!
//! ```text
//! offset  size  field
//! 0       8     discriminator
//! 8       32    wallet_id
//! 40      33    active_key
//! 73      8     nonce               u64 LE
//! 81      1     attested
//! 82      198   guardians           3 slots of 66 bytes, below
//! 280     1     rotation pending    0 or 1
//! 281     33    rotation new_key
//! 314     8     rotation proposed_at  i64 LE
//! 322     1     rotation proposed_by  guardian slot
//! 323     1     state_bump
//! 324     1     vault_bump
//!
//! guardian slot i, at 82 + 66·i
//! +0      1     kind                0 none, 1 P256, 2 WebAuthn
//! +1      33    key
//! +34     32    rp_id_hash          SHA-256 of the passkey's rpId, zeros otherwise
//! ```
//!
//! Every field has a fixed size: an empty guardian slot or no pending
//! rotation is all zeros, never a shorter encoding. The offsets hold
//! whatever the wallet holds, and a removed key leaves no trace to match.

use crate::constants::{COMPRESSED_PUBKEY_LEN, MAX_GUARDIANS};

/// Anchor's account discriminator, before the fields.
pub const DISCRIMINATOR_LEN: usize = 8;

pub const WALLET_ID_OFFSET: usize = DISCRIMINATOR_LEN;
pub const ACTIVE_KEY_OFFSET: usize = WALLET_ID_OFFSET + 32;
pub const NONCE_OFFSET: usize = ACTIVE_KEY_OFFSET + COMPRESSED_PUBKEY_LEN;
pub const ATTESTED_OFFSET: usize = NONCE_OFFSET + 8;

pub const GUARDIANS_OFFSET: usize = ATTESTED_OFFSET + 1;
/// kind, key, rp_id_hash
pub const GUARDIAN_SLOT_LEN: usize = 1 + COMPRESSED_PUBKEY_LEN + 32;

/// `kind` values of a guardian slot.
pub const GUARDIAN_KIND_NONE: u8 = 0;
pub const GUARDIAN_KIND_P256: u8 = 1;
pub const GUARDIAN_KIND_WEBAUTHN: u8 = 2;

pub const ROTATION_OFFSET: usize = GUARDIANS_OFFSET + MAX_GUARDIANS * GUARDIAN_SLOT_LEN;
pub const ROTATION_NEW_KEY_OFFSET: usize = ROTATION_OFFSET + 1;
pub const ROTATION_PROPOSED_AT_OFFSET: usize = ROTATION_NEW_KEY_OFFSET + COMPRESSED_PUBKEY_LEN;
pub const ROTATION_PROPOSED_BY_OFFSET: usize = ROTATION_PROPOSED_AT_OFFSET + 8;

pub const STATE_BUMP_OFFSET: usize = ROTATION_PROPOSED_BY_OFFSET + 1;
pub const VAULT_BUMP_OFFSET: usize = STATE_BUMP_OFFSET + 1;

/// The account's size, discriminator included: the `dataSize` filter that
/// leaves out accounts of another layout.
pub const STATE_LEN: usize = VAULT_BUMP_OFFSET + 1;

/// Offset of guardian slot `index`: its `kind` byte.
pub const fn guardian_kind_offset(index: usize) -> usize {
    GUARDIANS_OFFSET + index * GUARDIAN_SLOT_LEN
}

/// Offset of the key in guardian slot `index`.
pub const fn guardian_key_offset(index: usize) -> usize {
    guardian_kind_offset(index) + 1
}

/// Offset of the rpId hash in guardian slot `index`.
pub const fn guardian_rp_id_hash_offset(index: usize) -> usize {
    guardian_key_offset(index) + COMPRESSED_PUBKEY_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_match_the_documented_layout() {
        assert_eq!(ACTIVE_KEY_OFFSET, 40);
        assert_eq!(GUARDIANS_OFFSET, 82);
        assert_eq!(GUARDIAN_SLOT_LEN, 66);
        assert_eq!(
            [0, 1, 2].map(guardian_key_offset),
            [83, 149, 215],
            "keys of the three guardian slots"
        );
        assert_eq!(guardian_rp_id_hash_offset(0), 116);
        assert_eq!(ROTATION_OFFSET, 280);
        assert_eq!(ROTATION_NEW_KEY_OFFSET, 281);
        assert_eq!(ROTATION_PROPOSED_AT_OFFSET, 314);
        assert_eq!(ROTATION_PROPOSED_BY_OFFSET, 322);
        assert_eq!(STATE_BUMP_OFFSET, 323);
        assert_eq!(VAULT_BUMP_OFFSET, 324);
        assert_eq!(STATE_LEN, 325);
    }
}
