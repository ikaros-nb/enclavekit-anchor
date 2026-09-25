use sha2::{Digest, Sha256};

use crate::constants::COMPRESSED_PUBKEY_LEN;

pub fn wallet_id(compressed_pubkey: &[u8; COMPRESSED_PUBKEY_LEN]) -> [u8; 32] {
    Sha256::digest(compressed_pubkey).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_id_is_sha256_of_the_compressed_key() {
        // Reference computed outside Rust:
        // python3 -c "import hashlib; print(hashlib.sha256(bytes([2]*33)).hexdigest())"
        let expected: [u8; 32] = [
            0x7f, 0x2f, 0x54, 0xff, 0x94, 0x45, 0x9f, 0x3a, 0xc4, 0xd1, 0x9d, 0x32, 0x19, 0xce,
            0x6e, 0xf0, 0x68, 0x68, 0xeb, 0x8c, 0x72, 0xe6, 0xd8, 0x4c, 0xc3, 0x58, 0xbc, 0x76,
            0x9b, 0x23, 0x11, 0x3a,
        ];
        assert_eq!(wallet_id(&[0x02; 33]), expected);
    }

    #[test]
    fn different_keys_give_different_ids() {
        let a = wallet_id(&[0x02; 33]);
        let mut other_key = [0x02; 33];
        other_key[32] ^= 1;
        assert_ne!(wallet_id(&other_key), a);
    }

    #[test]
    fn wallet_id_is_deterministic() {
        assert_eq!(wallet_id(&[0x03; 33]), wallet_id(&[0x03; 33]));
    }
}
