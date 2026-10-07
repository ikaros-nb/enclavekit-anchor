use anchor_lang::prelude::*;

use crate::constants::{COMPRESSED_PUBKEY_LEN, MAX_GUARDIANS, ROTATION_DELAY, ROTATION_WINDOW};

/// Every field has a fixed size, so each one sits at the same offset in
/// every wallet: a device finds the wallets that name its key with
/// `getProgramAccounts`. The offsets are in `enclavekit_encoding::state`.
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
    /// Fixed-size slots, an empty one all zeros: rent is per byte.
    pub guardians: [GuardianSlot; MAX_GUARDIANS],
    /// Guardian-proposed rotation waiting for its timelock.
    pub rotation: RotationSlot,
    pub state_bump: u8,
    pub vault_bump: u8,
}

// Devices filter on the crate's offsets: both must describe this struct.
const _: () = assert!(
    SmartWallet::DISCRIMINATOR.len() + SmartWallet::INIT_SPACE
        == enclavekit_encoding::state::STATE_LEN
);

impl SmartWallet {
    /// The state `init_if_needed` just made, all zeros: the first action
    /// fills it.
    pub fn is_new(&self) -> bool {
        self.active_key == [0u8; COMPRESSED_PUBKEY_LEN]
    }

    /// Slot of the P-256 guardian `key`, if the wallet names it.
    pub fn p256_guardian(&self, key: &[u8; COMPRESSED_PUBKEY_LEN]) -> Option<usize> {
        self.guardians
            .iter()
            .position(|slot| slot.kind == GuardianKind::P256 && slot.key == *key)
    }
}

/// A guardian as stored: `key` sits at the same offset whatever its kind.
#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone, Copy, PartialEq, Eq, Debug)]
pub struct GuardianSlot {
    pub kind: GuardianKind,
    pub key: [u8; COMPRESSED_PUBKEY_LEN],
    /// SHA-256 of a passkey's rpId, to compare with its authenticatorData.
    /// Zeros for any other kind.
    pub rp_id_hash: [u8; 32],
}

impl GuardianSlot {
    pub const EMPTY: Self = Self {
        kind: GuardianKind::None,
        key: [0; COMPRESSED_PUBKEY_LEN],
        rp_id_hash: [0; 32],
    };
}

/// One byte: 0 none, 1 P256, 2 WebAuthn, like `Guardian`'s variants.
#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone, Copy, PartialEq, Eq, Debug)]
pub enum GuardianKind {
    None,
    P256,
    WebAuthn,
}

impl From<Guardian> for GuardianSlot {
    fn from(guardian: Guardian) -> Self {
        match guardian {
            Guardian::None => Self::EMPTY,
            Guardian::P256(key) => Self {
                kind: GuardianKind::P256,
                key,
                ..Self::EMPTY
            },
            // Never stored in v1: `set_guardians` rejects it first.
            Guardian::WebAuthn(key) => Self {
                kind: GuardianKind::WebAuthn,
                key,
                ..Self::EMPTY
            },
        }
    }
}

/// A guardian's proposal, or all zeros. An `Option` would shrink to one
/// byte when empty and move what follows; here `new_key` stays at the same
/// offset, and a cleared proposal leaves no key behind to match.
#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone)]
pub struct RotationSlot {
    pub pending: bool,
    pub proposal: PendingRotation,
}

impl RotationSlot {
    pub const EMPTY: Self = Self {
        pending: false,
        proposal: PendingRotation {
            new_key: [0; COMPRESSED_PUBKEY_LEN],
            proposed_at: 0,
            proposed_by: 0,
        },
    };

    pub fn new(proposal: PendingRotation) -> Self {
        Self {
            pending: true,
            proposal,
        }
    }

    pub fn get(&self) -> Option<&PendingRotation> {
        self.pending.then_some(&self.proposal)
    }

    /// Empties the slot and returns what it held.
    pub fn take(&mut self) -> Option<PendingRotation> {
        let slot = core::mem::replace(self, Self::EMPTY);
        slot.pending.then_some(slot.proposal)
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone)]
pub struct PendingRotation {
    pub new_key: [u8; COMPRESSED_PUBKEY_LEN],
    pub proposed_at: i64,
    /// The guardian's slot.
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

/// A guardian as `set_guardians` takes it and as the user signs it.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
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
