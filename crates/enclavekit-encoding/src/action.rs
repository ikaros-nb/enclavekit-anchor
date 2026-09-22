use borsh::{BorshDeserialize, BorshSerialize};

pub const MAX_GUARDIANS: usize = 3;
pub const COMPRESSED_PUBKEY_LEN: usize = 33;

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Eq, Debug)]
pub enum Guardian {
    None,
    P256([u8; COMPRESSED_PUBKEY_LEN]),
    WebAuthn([u8; COMPRESSED_PUBKEY_LEN]),
}

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Eq, Debug)]
pub enum Action {
    TransferSol { to: [u8; 32], lamports: u64 },
    TransferToken { mint: [u8; 32], to: [u8; 32], amount: u64 },
    ProposeRotation { new_key: [u8; 33] },
    CancelRotation,
    SetGuardians { guardians: [Guardian; MAX_GUARDIANS] },
    CloseWallet { rent_to: [u8; 32] },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_variant_is_its_index_only() {
        assert_eq!(borsh::to_vec(&Action::CancelRotation).unwrap(), [3]);
    }

    #[test]
    fn transfer_sol_is_index_then_fields_in_order() {
        let action = Action::TransferSol {
            to: [0x11; 32],
            lamports: 500_000_000,
        };

        let mut expected = vec![0u8]; // variant index
        expected.extend_from_slice(&[0x11; 32]);
        expected.extend_from_slice(&500_000_000u64.to_le_bytes());

        assert_eq!(borsh::to_vec(&action).unwrap(), expected);
    }

    #[test]
    fn every_variant_round_trips() {
        let actions = [
            Action::TransferSol {
                to: [0x11; 32],
                lamports: 1,
            },
            Action::TransferToken {
                mint: [0x22; 32],
                to: [0x33; 32],
                amount: 2,
            },
            Action::ProposeRotation { new_key: [0x44; 33] },
            Action::CancelRotation,
            Action::SetGuardians {
                guardians: [Guardian::P256([0x55; 33]), Guardian::None, Guardian::None],
            },
            Action::CloseWallet { rent_to: [0x66; 32] },
        ];

        for (index, action) in actions.iter().enumerate() {
            let bytes = borsh::to_vec(action).unwrap();
            assert_eq!(bytes[0] as usize, index, "variant index of {action:?}");

            let decoded = Action::try_from_slice(&bytes).unwrap();
            assert_eq!(&decoded, action);
        }
    }
}
