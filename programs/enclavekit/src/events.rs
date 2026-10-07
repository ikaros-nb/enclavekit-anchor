use anchor_lang::prelude::*;

use crate::{Guardian, COMPRESSED_PUBKEY_LEN, MAX_GUARDIANS};

// Every handler emits through a self-CPI (`emit_cpi!`): the event lands in
// the transaction's inner instructions, which RPCs keep in full where they
// may truncate logs. `wallet_id` comes first in each, for an indexer to
// filter on.

/// The wallet's first action created its state. Comes before that action's
/// own event.
#[event]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletCreated {
    pub wallet_id: [u8; 32],
    /// The key that made the wallet: `wallet_id` is its SHA-256.
    pub key: [u8; COMPRESSED_PUBKEY_LEN],
}

#[event]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolTransferred {
    pub wallet_id: [u8; 32],
    pub to: Pubkey,
    pub lamports: u64,
    /// What the vault paid the relayer back.
    pub relayer_fee: u64,
}

/// `lamports`: what the vault held, the refund aside, read as it executed.
/// The state stays.
#[event]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultSwept {
    pub wallet_id: [u8; 32],
    pub to: Pubkey,
    pub lamports: u64,
    pub relayer_fee: u64,
}

/// Same amounts as `VaultSwept`, then the state is gone. Its rent goes to
/// the relayer, which advanced it: not counted in `relayer_fee`.
#[event]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletClosed {
    pub wallet_id: [u8; 32],
    pub to: Pubkey,
    pub lamports: u64,
    pub relayer_fee: u64,
}

/// The whole list, as stored. Ends any pending rotation.
#[event]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardiansSet {
    pub wallet_id: [u8; 32],
    pub guardians: [Guardian; MAX_GUARDIANS],
}

/// A guardian proposed to move the wallet to `new_key`. The owner can
/// cancel until `opens_at`; from then anyone can confirm.
#[event]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationProposed {
    pub wallet_id: [u8; 32],
    pub new_key: [u8; COMPRESSED_PUBKEY_LEN],
    /// The guardian's key, the one that signed.
    pub guardian: [u8; COMPRESSED_PUBKEY_LEN],
    pub opens_at: i64,
}

#[event]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationCancelled {
    pub wallet_id: [u8; 32],
    /// The key the cancelled proposal moved the wallet to.
    pub new_key: [u8; COMPRESSED_PUBKEY_LEN],
}

/// `new_key` is now the wallet's active key, and any pending rotation ends.
/// `recovery`: a guardian's proposal confirmed past its delay. Otherwise
/// the active key moved the wallet itself, at once.
#[event]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRotated {
    pub wallet_id: [u8; 32],
    pub new_key: [u8; COMPRESSED_PUBKEY_LEN],
    pub recovery: bool,
}
