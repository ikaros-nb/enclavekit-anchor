use anchor_lang::prelude::*;

use crate::{
    authorization::{
        refund_relayer, require_active_key, verify_enclave_authorization, Authorization,
    },
    error::EnclaveKitError,
    SmartWallet, VAULT_SEED, WALLET_SEED,
};

use enclavekit_encoding::action::Action;

#[derive(Accounts)]
#[instruction(wallet_id: [u8; 32])]
pub struct CancelRotation<'info> {
    /// Must already exist: a wallet never used has nothing to cancel.
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

impl<'info> CancelRotation<'info> {
    pub fn cancel(&mut self, authorization: Authorization, relayer_fee: u64) -> Result<()> {
        let action = Action::CancelRotation;
        let (state_bump, vault_bump) = (self.wallet.state_bump, self.wallet.vault_bump);
        let signer = verify_enclave_authorization(
            &mut self.wallet,
            &self.instructions_sysvar,
            &authorization,
            &action,
            state_bump,
            vault_bump,
        )?;
        require_active_key(&self.wallet, &signer)?;

        require!(
            self.wallet.rotation.is_some(),
            EnclaveKitError::NoPendingRotation
        );
        self.wallet.rotation = None;

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
