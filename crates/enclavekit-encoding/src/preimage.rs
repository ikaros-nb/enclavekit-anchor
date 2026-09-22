//! The bytes the Secure Enclave signs.
//!
//! ```text
//! offset  size  field
//! 0       16    DOMAIN_TAG          protocol + version, fixed length
//! 16      32    program_id          no replay against another program
//! 48      32    wallet_id           this wallet, not another
//! 80      8     nonce               u64 LE
//! 88      8     expires_at          i64 LE, unix seconds, checked against Clock
//! 96      8     max_relayer_fee     u64 LE, lamports the user approved
//! 104     n     action              borsh(Action), little-endian throughout
//! ```
//!
//! Everything before `action` has a fixed size, so `HEADER_LEN` is a constant
//! and the action always starts at the same offset.

use borsh::BorshSerialize;

use crate::action::Action;

/// Protocol name and version, padded with zeros to a fixed length.
pub const DOMAIN_TAG: [u8; 16] = *b"enclavekit:v1\0\0\0";

/// Size of every field before the action.
pub const HEADER_LEN: usize = 16 + 32 + 32 + 8 + 8 + 8;

pub const PROGRAM_ID_OFFSET: usize = 16;
pub const WALLET_ID_OFFSET: usize = 48;
pub const NONCE_OFFSET: usize = 80;
pub const EXPIRES_AT_OFFSET: usize = 88;
pub const MAX_RELAYER_FEE_OFFSET: usize = 96;
pub const ACTION_OFFSET: usize = HEADER_LEN;

#[derive(Clone)]
pub struct Preimage<'a> {
    pub program_id: [u8; 32],
    pub wallet_id: [u8; 32],
    pub nonce: u64,
    pub expires_at: i64,
    pub max_relayer_fee: u64,
    pub action: &'a Action,
}

impl Preimage<'_> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 128);
        out.extend_from_slice(&DOMAIN_TAG);
        out.extend_from_slice(&self.program_id);
        out.extend_from_slice(&self.wallet_id);
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.expires_at.to_le_bytes());
        out.extend_from_slice(&self.max_relayer_fee.to_le_bytes());
        self.action
            .serialize(&mut out)
            .expect("borsh serialisation into a Vec should succeed");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_action() -> Action {
        Action::TransferSol {
            to: [0x11; 32],
            lamports: 500_000_000,
        }
    }

    fn sample<'a>(action: &'a Action) -> Preimage<'a> {
        Preimage {
            program_id: [0xAA; 32],
            wallet_id: [0xBB; 32],
            nonce: 7,
            expires_at: 1_700_000_000,
            max_relayer_fee: 10_000,
            action,
        }
    }

    #[test]
    fn header_offsets_match_layout() {
        let action = sample_action();
        let bytes = sample(&action).to_bytes();

        assert_eq!(&bytes[..16], &DOMAIN_TAG);
        assert_eq!(&bytes[PROGRAM_ID_OFFSET..WALLET_ID_OFFSET], &[0xAA; 32]);
        assert_eq!(&bytes[WALLET_ID_OFFSET..NONCE_OFFSET], &[0xBB; 32]);
        assert_eq!(&bytes[NONCE_OFFSET..EXPIRES_AT_OFFSET], &7u64.to_le_bytes());
        assert_eq!(
            &bytes[EXPIRES_AT_OFFSET..MAX_RELAYER_FEE_OFFSET],
            &1_700_000_000i64.to_le_bytes()
        );
        assert_eq!(
            &bytes[MAX_RELAYER_FEE_OFFSET..ACTION_OFFSET],
            &10_000u64.to_le_bytes()
        );
        assert_eq!(&bytes[ACTION_OFFSET..], &borsh::to_vec(&action).unwrap());
    }

    #[test]
    fn transfer_sol_preimage_has_expected_length() {
        let action = sample_action();
        // TransferSol = 1 (variant tag) + 32 (to) + 8 (lamports)
        assert_eq!(sample(&action).to_bytes().len(), HEADER_LEN + 1 + 32 + 8);
    }

    #[test]
    fn changing_any_field_changes_the_bytes() {
        let action = sample_action();
        let base = sample(&action);
        let reference = base.to_bytes();

        let mut other = base.clone();
        other.nonce += 1;
        assert_ne!(other.to_bytes(), reference);

        let mut other = base.clone();
        other.max_relayer_fee += 1;
        assert_ne!(other.to_bytes(), reference);

        let mut other = base.clone();
        other.wallet_id[0] ^= 1;
        assert_ne!(other.to_bytes(), reference);

        let other_action = Action::TransferSol {
            to: [0x11; 32],
            lamports: 500_000_001,
        };
        assert_ne!(sample(&other_action).to_bytes(), reference);
    }
}
