//! The state account byte by byte, at the crate's offsets: the ones a
//! device filters on with `getProgramAccounts` to find its wallets.

mod common;

use anchor_lang::prelude::Pubkey;
use anchor_lang::Discriminator;
use common::{
    confirm_rotation_instruction, vault_pda, wallet_pda, CancelRotationRequest, EnclaveKey,
    EnclaveRequest, Env, ProposeRotationRequest, SetGuardiansRequest,
};
use enclavekit::{state::Guardian, SmartWallet, MAX_GUARDIANS, ROTATION_DELAY};
use enclavekit_encoding::state::{
    guardian_key_offset, guardian_kind_offset, guardian_rp_id_hash_offset, ACTIVE_KEY_OFFSET,
    ATTESTED_OFFSET, DISCRIMINATOR_LEN, GUARDIANS_OFFSET, GUARDIAN_KIND_P256, GUARDIAN_SLOT_LEN,
    NONCE_OFFSET, ROTATION_NEW_KEY_OFFSET, ROTATION_OFFSET, ROTATION_PROPOSED_AT_OFFSET,
    ROTATION_PROPOSED_BY_OFFSET, STATE_BUMP_OFFSET, STATE_LEN, VAULT_BUMP_OFFSET, WALLET_ID_OFFSET,
};
use solana_signer::Signer;

const VAULT_FUNDING: u64 = 1_000_000_000;
const MAX_RELAYER_FEE: u64 = 100_000;
const RELAYER_FEE: u64 = 50_000;

/// A wallet that names two guardians, in slots 0 and 2: slot 1 stays empty.
struct Layout {
    env: Env,
    owner: EnclaveKey,
    guardians: [EnclaveKey; 2],
    wallet_id: [u8; 32],
    nonce: u64,
}

impl Layout {
    fn new() -> Self {
        let mut env = Env::new();
        let owner = EnclaveKey::from_seed([7u8; 32]);
        let wallet_id = owner.wallet_id();
        env.svm
            .airdrop(&vault_pda(&wallet_id), VAULT_FUNDING)
            .unwrap();

        let mut layout = Self {
            env,
            owner: owner.clone(),
            guardians: [
                EnclaveKey::from_seed([9u8; 32]),
                EnclaveKey::from_seed([10u8; 32]),
            ],
            wallet_id,
            nonce: 0,
        };
        let set_guardians = layout.set_guardians([
            Guardian::P256(layout.guardians[0].compressed_pubkey()),
            Guardian::None,
            Guardian::P256(layout.guardians[1].compressed_pubkey()),
        ]);
        layout.act(&owner, &set_guardians);
        layout
    }

    /// Sends an enclave-authorised call that must pass and moves the nonce on.
    fn act(&mut self, signer: &EnclaveKey, request: &impl EnclaveRequest) {
        let instructions = request.sign(signer, &self.env.payer.pubkey());
        self.env
            .send(&instructions)
            .unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs));
        self.nonce += 1;
    }

    fn set_guardians(&self, guardians: [Guardian; MAX_GUARDIANS]) -> SetGuardiansRequest {
        SetGuardiansRequest {
            wallet_id: self.wallet_id,
            guardians,
            nonce: self.nonce,
            expires_at: self.env.unix_timestamp() + 60,
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        }
    }

    fn propose(&self, new_key: &EnclaveKey) -> ProposeRotationRequest {
        ProposeRotationRequest {
            wallet_id: self.wallet_id,
            new_key: new_key.compressed_pubkey(),
            nonce: self.nonce,
            expires_at: self.env.unix_timestamp() + 60,
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        }
    }

    fn cancel(&self) -> CancelRotationRequest {
        CancelRotationRequest {
            wallet_id: self.wallet_id,
            nonce: self.nonce,
            expires_at: self.env.unix_timestamp() + 60,
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        }
    }

    /// The state account's data, as an RPC returns it.
    fn data(&self) -> Vec<u8> {
        self.env
            .svm
            .get_account(&wallet_pda(&self.wallet_id))
            .expect("the first action created the state")
            .data
    }
}

/// `N` bytes of `data` from `offset`.
fn at<const N: usize>(data: &[u8], offset: usize) -> [u8; N] {
    data[offset..offset + N].try_into().unwrap()
}

#[test]
fn every_field_sits_at_its_offset() {
    let mut layout = Layout::new();
    let new_device = EnclaveKey::from_seed([11u8; 32]);
    let propose = layout.propose(&new_device);
    layout.act(&layout.guardians[1].clone(), &propose);
    let proposed_at = layout.env.unix_timestamp();

    let data = layout.data();
    assert_eq!(data.len(), STATE_LEN);
    assert_eq!(&data[..DISCRIMINATOR_LEN], SmartWallet::DISCRIMINATOR);
    assert_eq!(at::<32>(&data, WALLET_ID_OFFSET), layout.wallet_id);
    assert_eq!(
        at::<33>(&data, ACTIVE_KEY_OFFSET),
        layout.owner.compressed_pubkey()
    );
    assert_eq!(at::<8>(&data, NONCE_OFFSET), 2u64.to_le_bytes());
    assert_eq!(data[ATTESTED_OFFSET], 0);

    for (slot, guardian) in [(0, &layout.guardians[0]), (2, &layout.guardians[1])] {
        assert_eq!(data[guardian_kind_offset(slot)], GUARDIAN_KIND_P256);
        assert_eq!(
            at::<33>(&data, guardian_key_offset(slot)),
            guardian.compressed_pubkey()
        );
        assert_eq!(at::<32>(&data, guardian_rp_id_hash_offset(slot)), [0; 32]);
    }
    assert_eq!(
        data[guardian_kind_offset(1)..guardian_kind_offset(2)],
        [0; GUARDIAN_SLOT_LEN]
    );

    // The proposal of the guardian in slot 2.
    assert_eq!(data[ROTATION_OFFSET], 1);
    assert_eq!(
        at::<33>(&data, ROTATION_NEW_KEY_OFFSET),
        new_device.compressed_pubkey()
    );
    assert_eq!(
        at::<8>(&data, ROTATION_PROPOSED_AT_OFFSET),
        proposed_at.to_le_bytes()
    );
    assert_eq!(data[ROTATION_PROPOSED_BY_OFFSET], 2);

    let (_, state_bump) = Pubkey::find_program_address(
        &[enclavekit::WALLET_SEED, &layout.wallet_id],
        &enclavekit::id(),
    );
    let (_, vault_bump) = Pubkey::find_program_address(
        &[enclavekit::VAULT_SEED, &layout.wallet_id],
        &enclavekit::id(),
    );
    assert_eq!(data[STATE_BUMP_OFFSET], state_bump);
    assert_eq!(data[VAULT_BUMP_OFFSET], vault_bump);
}

#[test]
fn a_cancelled_proposal_leaves_only_zeros() {
    let mut layout = Layout::new();
    let propose = layout.propose(&EnclaveKey::from_seed([11u8; 32]));
    layout.act(&layout.guardians[0].clone(), &propose);

    let cancel = layout.cancel();
    layout.act(&layout.owner.clone(), &cancel);

    let data = layout.data();
    assert_eq!(
        data[ROTATION_OFFSET..STATE_BUMP_OFFSET],
        [0; STATE_BUMP_OFFSET - ROTATION_OFFSET]
    );
}

#[test]
fn a_confirmed_recovery_moves_the_new_key_to_active_key() {
    let mut layout = Layout::new();
    let new_device = EnclaveKey::from_seed([11u8; 32]);
    let propose = layout.propose(&new_device);
    layout.act(&layout.guardians[0].clone(), &propose);

    layout.env.warp(ROTATION_DELAY);
    layout
        .env
        .send(&[confirm_rotation_instruction(&layout.wallet_id)])
        .unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs));

    let data = layout.data();
    assert_eq!(
        at::<33>(&data, ACTIVE_KEY_OFFSET),
        new_device.compressed_pubkey()
    );
    assert_eq!(
        data[ROTATION_OFFSET..STATE_BUMP_OFFSET],
        [0; STATE_BUMP_OFFSET - ROTATION_OFFSET]
    );
}

#[test]
fn removed_guardians_leave_only_zeros() {
    let mut layout = Layout::new();
    let set_guardians = layout.set_guardians([Guardian::None; MAX_GUARDIANS]);
    layout.act(&layout.owner.clone(), &set_guardians);

    let data = layout.data();
    assert_eq!(
        data[GUARDIANS_OFFSET..ROTATION_OFFSET],
        [0; MAX_GUARDIANS * GUARDIAN_SLOT_LEN]
    );
}
