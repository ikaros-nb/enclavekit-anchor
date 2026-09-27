//! Writes the conformance vectors to `vectors/` at the repository root.
//!
//! Every input is fixed and P-256 signing is deterministic (RFC 6979).
//!
//! ```bash
//! cargo run -p gen-vectors
//! ```

use std::{
    fs,
    path::{Path, PathBuf},
};

use anchor_lang::prelude::Pubkey;
use enclavekit::{VAULT_SEED, WALLET_SEED};
use enclavekit_encoding::wallet::wallet_id;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::sec1::ToSec1Point;
use serde::{Serialize, Serializer};

/// Private scalar of the test key.
const PRIVATE_KEY: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

fn main() {
    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors");
    fs::create_dir_all(&out).expect("create vectors/");
    let out = out.canonicalize().expect("vectors/ exists");

    let key = EnclaveKey::from_seed(PRIVATE_KEY);
    write(&out, "key.json", &key_vector(&key));
}

// --- key.json -------------------------------------------------------------

#[derive(Serialize)]
struct KeyVector {
    private_key: Hex,
    compressed_pubkey: Hex,
    wallet_id: Hex,
    program_id: String,
    wallet: Pda,
    vault: Pda,
}

#[derive(Serialize)]
struct Pda {
    address: String,
    bump: u8,
}

impl Pda {
    fn find(seeds: &[&[u8]], program_id: &Pubkey) -> Self {
        let (address, bump) = Pubkey::find_program_address(seeds, program_id);
        Self {
            address: address.to_string(),
            bump,
        }
    }
}

fn key_vector(key: &EnclaveKey) -> KeyVector {
    let wallet_id = key.wallet_id();
    let program_id = enclavekit::id();
    KeyVector {
        private_key: PRIVATE_KEY.into(),
        compressed_pubkey: key.compressed_pubkey().into(),
        wallet_id: wallet_id.into(),
        program_id: program_id.to_string(),
        wallet: Pda::find(&[WALLET_SEED, &wallet_id], &program_id),
        vault: Pda::find(&[VAULT_SEED, &wallet_id], &program_id),
    }
}

// --- the test key ---------------------------------------------------------

/// A P-256 key standing in for the Secure Enclave.
struct EnclaveKey(SigningKey);

impl EnclaveKey {
    fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_slice(&seed).expect("seed is a valid P-256 scalar"))
    }

    /// Compressed SEC1 encoding: 0x02 or 0x03 followed by the 32-byte x coordinate.
    fn compressed_pubkey(&self) -> [u8; 33] {
        let point = self.0.verifying_key().as_affine().to_sec1_point(true);
        point
            .as_bytes()
            .try_into()
            .expect("compressed point is 33 bytes")
    }

    fn wallet_id(&self) -> [u8; 32] {
        wallet_id(&self.compressed_pubkey())
    }
}

// --- output helpers -------------------------------------------------------

/// Bytes written as a lowercase hex string.
struct Hex(Vec<u8>);

impl<const N: usize> From<[u8; N]> for Hex {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes.to_vec())
    }
}

impl From<Vec<u8>> for Hex {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Serialize for Hex {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let hex: String = self.0.iter().map(|b| format!("{b:02x}")).collect();
        serializer.serialize_str(&hex)
    }
}

fn write<T: Serialize>(dir: &Path, name: &str, value: &T) {
    let path = dir.join(name);
    let json = serde_json::to_string_pretty(value).expect("vector is serialisable");
    fs::write(&path, json + "\n").unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    println!("wrote {}", path.display());
}
