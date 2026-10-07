mod common;

use anchor_lang::error::ErrorCode;
use anchor_lang::event::EVENT_IX_TAG_LE;
use anchor_lang::prelude::Pubkey;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::Event;
use common::{
    assert_failed_at, confirm_rotation_instruction, decode, emitted, event_authority, vault_pda,
    CancelRotationRequest, CloseWalletRequest, EnclaveKey, EnclaveRequest, Env,
    ProposeRotationRequest, SetGuardiansRequest, SweepVaultRequest, TransferSolRequest,
};
use enclavekit::{events::*, state::Guardian, ROTATION_DELAY};
use solana_signer::Signer;

const VAULT_FUNDING: u64 = 1_000_000_000;
const MAX_RELAYER_FEE: u64 = 100_000;
const RELAYER_FEE: u64 = 50_000;
const LAMPORTS: u64 = 10_000_000;

/// One wallet, its guardian, the device it may move to. Builds each request
/// at the wallet's next nonce.
struct Scenario {
    env: Env,
    key: EnclaveKey,
    guardian: EnclaveKey,
    new_key: EnclaveKey,
    to: Pubkey,
    nonce: u64,
}

impl Scenario {
    fn new() -> Self {
        let mut env = Env::new();
        let key = EnclaveKey::from_seed([7u8; 32]);
        env.svm
            .airdrop(&vault_pda(&key.wallet_id()), VAULT_FUNDING)
            .unwrap();
        Self {
            env,
            key,
            guardian: EnclaveKey::from_seed([9u8; 32]),
            new_key: EnclaveKey::from_seed([11u8; 32]),
            to: Pubkey::new_unique(),
            nonce: 0,
        }
    }

    fn wallet_id(&self) -> [u8; 32] {
        self.key.wallet_id()
    }

    fn expires_at(&self) -> i64 {
        self.env.unix_timestamp() + 60
    }

    /// Signs `request` with `signer` and returns what the program emitted.
    /// Panics with the logs if the transaction fails.
    fn send(&mut self, signer: &EnclaveKey, request: &impl EnclaveRequest) -> Vec<Vec<u8>> {
        let instructions = request.sign(signer, &self.env.payer.pubkey());
        let meta = self
            .env
            .send(&instructions)
            .unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs));
        self.nonce += 1;
        emitted(&meta)
    }

    fn transfer(&self, relayer_fee: u64) -> TransferSolRequest {
        TransferSolRequest {
            wallet_id: self.wallet_id(),
            to: self.to,
            lamports: LAMPORTS,
            nonce: self.nonce,
            expires_at: self.expires_at(),
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee,
        }
    }

    fn set_guardian(&self) -> SetGuardiansRequest {
        SetGuardiansRequest {
            wallet_id: self.wallet_id(),
            guardians: [
                Guardian::P256(self.guardian.compressed_pubkey()),
                Guardian::None,
                Guardian::None,
            ],
            nonce: self.nonce,
            expires_at: self.expires_at(),
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        }
    }

    fn propose(&self) -> ProposeRotationRequest {
        ProposeRotationRequest {
            wallet_id: self.wallet_id(),
            new_key: self.new_key.compressed_pubkey(),
            nonce: self.nonce,
            expires_at: self.expires_at(),
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        }
    }

    fn cancel(&self) -> CancelRotationRequest {
        CancelRotationRequest {
            wallet_id: self.wallet_id(),
            nonce: self.nonce,
            expires_at: self.expires_at(),
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        }
    }

    fn sweep(&self) -> SweepVaultRequest {
        SweepVaultRequest {
            wallet_id: self.wallet_id(),
            to: self.to,
            nonce: self.nonce,
            expires_at: self.expires_at(),
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        }
    }

    fn close(&self) -> CloseWalletRequest {
        CloseWalletRequest {
            wallet_id: self.wallet_id(),
            to: self.to,
            nonce: self.nonce,
            expires_at: self.expires_at(),
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        }
    }

    /// The guardian named, then its proposal toward `new_key`.
    fn guardian_proposes(&mut self) -> Vec<Vec<u8>> {
        let (key, guardian) = (self.key.clone(), self.guardian.clone());
        self.send(&key, &self.set_guardian());
        self.send(&guardian, &self.propose())
    }

    fn wallet_created(&self) -> WalletCreated {
        WalletCreated {
            wallet_id: self.wallet_id(),
            key: self.key.compressed_pubkey(),
        }
    }
}

#[test]
fn first_action_emits_wallet_created_before_its_own_event() {
    let mut scenario = Scenario::new();
    let key = scenario.key.clone();

    let events = scenario.send(&key, &scenario.transfer(RELAYER_FEE));

    assert_eq!(events.len(), 2);
    assert_eq!(decode(&events[0]), Some(scenario.wallet_created()));
    assert_eq!(
        decode(&events[1]),
        Some(SolTransferred {
            wallet_id: scenario.wallet_id(),
            to: scenario.to,
            lamports: LAMPORTS,
            relayer_fee: RELAYER_FEE,
        })
    );
}

#[test]
fn later_actions_emit_only_their_own_event() {
    let mut scenario = Scenario::new();
    let key = scenario.key.clone();
    scenario.send(&key, &scenario.transfer(RELAYER_FEE));

    let events = scenario.send(&key, &scenario.transfer(RELAYER_FEE));

    assert_eq!(events.len(), 1);
    assert!(decode::<SolTransferred>(&events[0]).is_some());
}

#[test]
fn the_event_reports_the_refund_paid_not_the_one_asked() {
    let mut scenario = Scenario::new();
    let key = scenario.key.clone();

    let events = scenario.send(&key, &scenario.transfer(MAX_RELAYER_FEE + 1));

    let event: SolTransferred = decode(&events[1]).unwrap();
    assert_eq!(event.relayer_fee, MAX_RELAYER_FEE);
}

#[test]
fn set_guardians_emits_the_whole_list() {
    let mut scenario = Scenario::new();
    let key = scenario.key.clone();
    let request = scenario.set_guardian();

    let events = scenario.send(&key, &request);

    assert_eq!(events.len(), 2);
    assert_eq!(decode(&events[0]), Some(scenario.wallet_created()));
    assert_eq!(
        decode(&events[1]),
        Some(GuardiansSet {
            wallet_id: scenario.wallet_id(),
            guardians: request.guardians,
        })
    );
}

#[test]
fn a_guardian_proposal_emits_who_proposed_and_when_it_opens() {
    let mut scenario = Scenario::new();
    let now = scenario.env.unix_timestamp();

    let events = scenario.guardian_proposes();

    assert_eq!(events.len(), 1);
    assert_eq!(
        decode(&events[0]),
        Some(RotationProposed {
            wallet_id: scenario.wallet_id(),
            new_key: scenario.new_key.compressed_pubkey(),
            guardian: scenario.guardian.compressed_pubkey(),
            opens_at: now + ROTATION_DELAY,
        })
    );
}

#[test]
fn cancel_emits_the_key_it_turned_down() {
    let mut scenario = Scenario::new();
    scenario.guardian_proposes();
    let key = scenario.key.clone();

    let events = scenario.send(&key, &scenario.cancel());

    assert_eq!(events.len(), 1);
    assert_eq!(
        decode(&events[0]),
        Some(RotationCancelled {
            wallet_id: scenario.wallet_id(),
            new_key: scenario.new_key.compressed_pubkey(),
        })
    );
}

#[test]
fn the_active_key_moving_the_wallet_emits_key_rotated_at_once() {
    let mut scenario = Scenario::new();
    let key = scenario.key.clone();
    scenario.send(&key, &scenario.set_guardian());

    let events = scenario.send(&key, &scenario.propose());

    assert_eq!(events.len(), 1);
    assert_eq!(
        decode(&events[0]),
        Some(KeyRotated {
            wallet_id: scenario.wallet_id(),
            new_key: scenario.new_key.compressed_pubkey(),
            recovery: false,
        })
    );
}

#[test]
fn a_confirmed_recovery_emits_key_rotated_as_a_recovery() {
    let mut scenario = Scenario::new();
    scenario.guardian_proposes();
    scenario.env.warp(ROTATION_DELAY);

    let meta = scenario
        .env
        .send(&[confirm_rotation_instruction(&scenario.wallet_id())])
        .unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs));
    let events = emitted(&meta);

    assert_eq!(events.len(), 1);
    assert_eq!(
        decode(&events[0]),
        Some(KeyRotated {
            wallet_id: scenario.wallet_id(),
            new_key: scenario.new_key.compressed_pubkey(),
            recovery: true,
        })
    );
}

#[test]
fn sweep_emits_what_left_the_vault() {
    let mut scenario = Scenario::new();
    let key = scenario.key.clone();

    let events = scenario.send(&key, &scenario.sweep());

    assert_eq!(events.len(), 2);
    assert_eq!(decode(&events[0]), Some(scenario.wallet_created()));
    let event: VaultSwept = decode(&events[1]).unwrap();
    assert_eq!(
        event,
        VaultSwept {
            wallet_id: scenario.wallet_id(),
            to: scenario.to,
            lamports: VAULT_FUNDING - RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        }
    );
    assert_eq!(scenario.env.balance(&scenario.to), event.lamports);
}

#[test]
fn close_emits_what_left_the_vault() {
    let mut scenario = Scenario::new();
    let key = scenario.key.clone();
    scenario.send(&key, &scenario.set_guardian());

    let events = scenario.send(&key, &scenario.close());

    assert_eq!(events.len(), 1);
    let event: WalletClosed = decode(&events[0]).unwrap();
    assert_eq!(
        event,
        WalletClosed {
            wallet_id: scenario.wallet_id(),
            to: scenario.to,
            lamports: VAULT_FUNDING - 2 * RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        }
    );
    assert_eq!(scenario.env.balance(&scenario.to), event.lamports);
}

#[test]
fn nobody_else_can_emit_an_event_as_the_program() {
    let mut scenario = Scenario::new();
    // Tag, discriminator, fields: what `emit_cpi!` sends.
    let mut data = EVENT_IX_TAG_LE.to_vec();
    data.extend(Event::data(&scenario.wallet_created()));
    let forged = Instruction {
        program_id: enclavekit::id(),
        accounts: vec![AccountMeta::new_readonly(event_authority(), false)],
        data,
    };

    let failed = scenario.env.send(&[forged]).unwrap_err();

    let code = u32::from(ErrorCode::ConstraintSigner);
    assert_failed_at(&failed, 0, &format!("Custom({code})"));
}
