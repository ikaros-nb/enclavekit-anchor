use anchor_lang::prelude::*;

use crate::{
    authorization::{refund_relayer, verify_enclave_authorization, Authorization},
    error::EnclaveKitError,
    events::{KeyRotated, RotationProposed},
    PendingRotation, RotationSlot, SmartWallet, COMPRESSED_PUBKEY_LEN, VAULT_SEED, WALLET_SEED,
};

use enclavekit_encoding::action::Action;

/// What a proposal did, depending on who signed it.
pub enum Proposal {
    /// The active key moved the wallet at once.
    Rotated(KeyRotated),
    /// A guardian started the timelock.
    Pending(RotationProposed),
}

#[event_cpi]
#[derive(Accounts)]
#[instruction(wallet_id: [u8; 32])]
pub struct ProposeRotation<'info> {
    /// Must already exist: a wallet never used has no key to rotate.
    #[account(
        mut,
        seeds = [WALLET_SEED, wallet_id.as_ref()],
        bump = wallet.state_bump,
    )]
    pub wallet: Account<'info, SmartWallet>,

    #[account(
        mut,
        seeds = [VAULT_SEED, wallet_id.as_ref()],
        bump = wallet.vault_bump,
    )]
    pub vault: SystemAccount<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// CHECK: pinned to the Instructions sysvar by the address constraint
    #[account(address = solana_instructions_sysvar::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

impl<'info> ProposeRotation<'info> {
    pub fn propose(
        &mut self,
        authorization: Authorization,
        new_key: [u8; COMPRESSED_PUBKEY_LEN],
        relayer_fee: u64,
    ) -> Result<Proposal> {
        // An all-zero active key means "never used" to verify_enclave_authorization.
        require!(
            new_key != [0u8; COMPRESSED_PUBKEY_LEN],
            EnclaveKitError::InvalidNewKey
        );

        let action = Action::ProposeRotation { new_key };
        let (state_bump, vault_bump) = (self.wallet.state_bump, self.wallet.vault_bump);
        let signer = verify_enclave_authorization(
            &mut self.wallet,
            &self.instructions_sysvar,
            &authorization,
            &action,
            state_bump,
            vault_bump,
        )?;

        let wallet_id = self.wallet.wallet_id;
        let proposal = if signer == self.wallet.active_key {
            // The owner still holds the key: no timelock, the swap is immediate.
            self.wallet.active_key = new_key;
            self.wallet.attested = false;
            self.wallet.rotation = RotationSlot::EMPTY;
            Proposal::Rotated(KeyRotated {
                wallet_id,
                new_key,
                recovery: false,
            })
        } else {
            let slot = self
                .wallet
                .p256_guardian(&signer)
                .ok_or(EnclaveKitError::NotAGuardian)?;

            let now = Clock::get()?.unix_timestamp;

            // A guardian may replace its own proposal, never another's, unless
            // that one ran out of its window: an abandoned proposal must not
            // lock the other guardians out while the owner is gone.
            if let Some(pending) = self.wallet.rotation.get() {
                require!(
                    pending.proposed_by as usize == slot || pending.is_expired(now),
                    EnclaveKitError::RotationSlotTaken
                );
            }

            let pending = PendingRotation {
                new_key,
                proposed_at: now,
                proposed_by: slot as u8,
            };
            let opens_at = pending.opens_at();
            self.wallet.rotation = RotationSlot::new(pending);
            Proposal::Pending(RotationProposed {
                wallet_id,
                new_key,
                guardian: signer,
                opens_at,
            })
        };

        refund_relayer(
            &self.wallet,
            &self.vault,
            &self.relayer,
            &self.system_program,
            relayer_fee,
            authorization.max_relayer_fee,
        )?;

        Ok(proposal)
    }
}
