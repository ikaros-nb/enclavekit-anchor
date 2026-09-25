//! The whole recovery story in one test.

mod common;

use anchor_lang::prelude::Pubkey;
use common::{
    assert_program_error, assert_program_error_at, confirm_rotation_instruction, vault_pda,
    CancelRotationRequest, EnclaveKey, EnclaveRequest, Env, ProposeRotationRequest,
    SetGuardiansRequest, TransferSolRequest,
};
use enclavekit::{error::EnclaveKitError, state::Guardian, ROTATION_DELAY};
use solana_signer::Signer;

const VAULT_FUNDING: u64 = 1_000_000_000;
const LAMPORTS: u64 = 100_000_000;
const MAX_RELAYER_FEE: u64 = 100_000;
const RELAYER_FEE: u64 = 50_000;

/// The wallet as the SDK sees it: which nonce comes next, when to expire.
struct Story {
    env: Env,
    wallet_id: [u8; 32],
    nonce: u64,
}

impl Story {
    fn relayer(&self) -> Pubkey {
        self.env.payer.pubkey()
    }

    fn expires_at(&self) -> i64 {
        self.env.unix_timestamp() + 60
    }

    /// Sends an enclave-authorised call that must pass and moves the nonce on.
    fn act(&mut self, signer: &EnclaveKey, request: &impl EnclaveRequest) {
        let instructions = request.sign(signer, &self.relayer());
        self.env
            .send(&instructions)
            .unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs));
        self.nonce += 1;
    }

    fn transfer(&self, to: Pubkey) -> TransferSolRequest {
        TransferSolRequest {
            wallet_id: self.wallet_id,
            to,
            lamports: LAMPORTS,
            nonce: self.nonce,
            expires_at: self.expires_at(),
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        }
    }

    fn set_guardians(&self, guardian: &EnclaveKey) -> SetGuardiansRequest {
        SetGuardiansRequest {
            wallet_id: self.wallet_id,
            guardians: [
                Guardian::P256(guardian.compressed_pubkey()),
                Guardian::None,
                Guardian::None,
            ],
            nonce: self.nonce,
            expires_at: self.expires_at(),
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        }
    }

    fn propose(&self, new_key: &EnclaveKey) -> ProposeRotationRequest {
        ProposeRotationRequest {
            wallet_id: self.wallet_id,
            new_key: new_key.compressed_pubkey(),
            nonce: self.nonce,
            expires_at: self.expires_at(),
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        }
    }

    fn cancel(&self) -> CancelRotationRequest {
        CancelRotationRequest {
            wallet_id: self.wallet_id,
            nonce: self.nonce,
            expires_at: self.expires_at(),
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        }
    }
}

#[test]
fn the_guardian_takes_over_a_lost_iphone() {
    let iphone_a = EnclaveKey::from_seed([7u8; 32]);
    let ipad = EnclaveKey::from_seed([9u8; 32]);
    let iphone_c = EnclaveKey::from_seed([11u8; 32]);
    let merchant = Pubkey::new_unique();

    let mut env = Env::new();
    let wallet_id = iphone_a.wallet_id();
    env.svm
        .airdrop(&vault_pda(&wallet_id), VAULT_FUNDING)
        .unwrap();
    let mut story = Story {
        env,
        wallet_id,
        nonce: 0,
    };

    // The first payment creates the wallet.
    story.act(&iphone_a, &story.transfer(merchant));
    assert_eq!(story.env.balance(&merchant), LAMPORTS);

    // The user adds their iPad as guardian.
    story.act(&iphone_a, &story.set_guardians(&ipad));

    // A false alarm: the iPad proposes a new device, the phone turns up and
    // its owner cancels before the timelock elapses.
    story.act(&ipad, &story.propose(&iphone_c));
    assert!(story.env.wallet(&wallet_id).unwrap().rotation.is_some());
    story.act(&iphone_a, &story.cancel());
    assert!(story.env.wallet(&wallet_id).unwrap().rotation.is_none());

    // The phone is really lost this time. The iPad proposes itself.
    story.act(&ipad, &story.propose(&ipad));

    // Too early: the proposal waits its 72 hours.
    let failed = story
        .env
        .send(&[confirm_rotation_instruction(&wallet_id)])
        .unwrap_err();
    assert_program_error_at(&failed, 0, EnclaveKitError::RotationTooEarly);

    // A guardian cannot pay either, even with its own proposal pending.
    let failed = story
        .env
        .send(&story.transfer(merchant).sign(&ipad, &story.relayer()))
        .unwrap_err();
    assert_program_error(&failed, EnclaveKitError::KeyMismatch);

    // 72 hours later, anyone confirms.
    story.env.warp(ROTATION_DELAY);
    story
        .env
        .send(&[confirm_rotation_instruction(&wallet_id)])
        .unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs));

    let wallet = story.env.wallet(&wallet_id).unwrap();
    assert_eq!(wallet.active_key, ipad.compressed_pubkey());
    // The iPad is now both the active key and guardian 0: confirm does not
    // touch the list, the app cleans it up with set_guardians.
    assert_eq!(
        wallet.guardians[0],
        Guardian::P256(ipad.compressed_pubkey())
    );
    assert!(!wallet.attested);
    assert!(wallet.rotation.is_none());
    assert_eq!(
        wallet.nonce, story.nonce,
        "confirm does not consume a nonce"
    );
    assert_eq!(wallet.wallet_id, wallet_id, "the identity survives");

    // The iPad pays from the same vault; whoever holds the lost phone cannot.
    story.act(&ipad, &story.transfer(merchant));
    assert_eq!(story.env.balance(&merchant), 2 * LAMPORTS);

    let failed = story
        .env
        .send(&story.transfer(merchant).sign(&iphone_a, &story.relayer()))
        .unwrap_err();
    assert_program_error(&failed, EnclaveKitError::KeyMismatch);
}
