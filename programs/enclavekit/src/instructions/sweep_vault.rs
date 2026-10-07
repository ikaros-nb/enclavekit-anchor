use anchor_lang::prelude::*;

use crate::{
    authorization::{
        refund_relayer, require_active_key, transfer_from_vault, verify_enclave_authorization,
        Authorization,
    },
    error::EnclaveKitError,
    SmartWallet, VAULT_SEED, WALLET_SEED,
};

use enclavekit_encoding::action::Action;

#[derive(Accounts)]
#[instruction(wallet_id: [u8; 32])]
pub struct SweepVault<'info> {
    #[account(
        init_if_needed,
        payer = relayer,
        space = SmartWallet::DISCRIMINATOR.len() + SmartWallet::INIT_SPACE,
        seeds = [WALLET_SEED, wallet_id.as_ref()],
        bump,
    )]
    pub wallet: Account<'info, SmartWallet>,

    /// Lamport holder owned by System, derived from wallet_id. Never has data.
    #[account(
        mut,
        seeds = [VAULT_SEED, wallet_id.as_ref()],
        bump,
    )]
    pub vault: SystemAccount<'info>,

    /// CHECK: any destination, bound by the signed preimage
    #[account(mut)]
    pub to: UncheckedAccount<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// CHECK: pinned to the Instructions sysvar by the address constraint
    #[account(address = solana_instructions_sysvar::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

impl<'info> SweepVault<'info> {
    /// Everything the vault holds goes to `to`, but the relayer's refund.
    /// The amount is read now, not signed: a deposit made after the
    /// approval leaves too. The vault ends at 0 and the runtime deletes it;
    /// the next deposit makes it again. The state stays, guardians included.
    pub fn sweep(
        &mut self,
        authorization: Authorization,
        relayer_fee: u64,
        bumps: &SweepVaultBumps,
    ) -> Result<()> {
        let action = Action::SweepVault {
            to: self.to.key().to_bytes(),
        };
        let signer = verify_enclave_authorization(
            &mut self.wallet,
            &self.instructions_sysvar,
            &authorization,
            &action,
            bumps.wallet,
            bumps.vault,
        )?;
        require_active_key(&self.wallet, &signer)?;

        let refund = relayer_fee.min(authorization.max_relayer_fee);
        let balance = self.vault.lamports();
        require!(balance >= refund, EnclaveKitError::InsufficientVaultBalance);

        transfer_from_vault(
            &self.wallet,
            &self.vault,
            self.to.to_account_info(),
            &self.system_program,
            balance - refund,
        )?;
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
