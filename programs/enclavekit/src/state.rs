use anchor_lang::prelude::*;

use crate::constants::{COMPRESSED_PUBKEY_LEN, MAX_GUARDIANS, ROTATION_DELAY, ROTATION_WINDOW};

#[account]
#[derive(InitSpace)]
pub struct SmartWallet {
    /// SHA256(initial compressed signing pubkey). Stable identity, survives rotations.
    pub wallet_id: [u8; 32],
    /// Compressed SEC1 P-256 key currently allowed to authorise actions.
    pub active_key: [u8; COMPRESSED_PUBKEY_LEN],
    /// Own anti-replay counter, bound into the signed preimage.
    pub nonce: u64,
    /// True once a verifier receipt for `active_key` was accepted. Reset on rotation.
    pub attested: bool,
    /// Guardian-proposed rotation waiting for its timelock.
    pub rotation: Option<PendingRotation>,
    /// Fixed-size list: rent is per byte.
    pub guardians: [Guardian; MAX_GUARDIANS],
    pub state_bump: u8,
    pub vault_bump: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone)]
pub struct PendingRotation {
    pub new_key: [u8; COMPRESSED_PUBKEY_LEN],
    pub proposed_at: i64,
    pub proposed_by: u8,
}

impl PendingRotation {
    /// First second at which `confirm_rotation` accepts it.
    pub fn opens_at(&self) -> i64 {
        self.proposed_at.saturating_add(ROTATION_DELAY)
    }

    /// Last second at which `confirm_rotation` accepts it.
    pub fn closes_at(&self) -> i64 {
        self.opens_at().saturating_add(ROTATION_WINDOW)
    }

    /// Past its window: nobody confirmed in time, it no longer blocks anyone.
    pub fn is_expired(&self, now: i64) -> bool {
        now > self.closes_at()
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Guardian {
    None,
    /// Another Apple device the user owns. Verified through the secp256r1 precompile.
    P256([u8; COMPRESSED_PUBKEY_LEN]),
    /// iCloud-synced passkey. Rejected by `set_guardians` in v1.
    WebAuthn([u8; COMPRESSED_PUBKEY_LEN]),
}

/// The preimage is built from the crate side.
impl From<Guardian> for enclavekit_encoding::action::Guardian {
    fn from(guardian: Guardian) -> Self {
        match guardian {
            Guardian::None => Self::None,
            Guardian::P256(key) => Self::P256(key),
            Guardian::WebAuthn(key) => Self::WebAuthn(key),
        }
    }
}
