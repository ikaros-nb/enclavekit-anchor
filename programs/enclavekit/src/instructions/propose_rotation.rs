use anchor_lang::prelude::*;

use crate::{
    authorization::{refund_relayer, verify_enclave_authorization, Authorization},
    error::EnclaveKitError,
    Guardian, PendingRotation, SmartWallet, COMPRESSED_PUBKEY_LEN, VAULT_SEED, WALLET_SEED,
};

use enclavekit_encoding::action::Action;

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
    ) -> Result<()> {
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

        if signer == self.wallet.active_key {
            // The owner still holds the key: no timelock, the swap is immediate.
            self.wallet.active_key = new_key;
            self.wallet.attested = false;
            self.wallet.rotation = None;
        } else {
            let slot = self
                .wallet
                .guardians
                .iter()
                .position(|guardian| *guardian == Guardian::P256(signer))
                .ok_or(EnclaveKitError::NotAGuardian)?;

            // A guardian may replace its own proposal, never another's.
            if let Some(pending) = &self.wallet.rotation {
                require!(
                    pending.proposed_by as usize == slot,
                    EnclaveKitError::RotationSlotTaken
                );
            }

            self.wallet.rotation = Some(PendingRotation {
                new_key,
                proposed_at: Clock::get()?.unix_timestamp,
                proposed_by: slot as u8,
            });
        }

        refund_relayer(
            &self.wallet,
            &self.vault,
            &self.relayer,
            &self.system_program,
            relayer_fee,
            authorization.max_relayer_fee,
        )
    }
}
