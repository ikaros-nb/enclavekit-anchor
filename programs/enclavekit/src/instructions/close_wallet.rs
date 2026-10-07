use anchor_lang::prelude::*;

use crate::{
    authorization::{
        require_active_key, transfer_from_vault, verify_enclave_authorization, Authorization,
    },
    SmartWallet, VAULT_SEED, WALLET_SEED,
};

use enclavekit_encoding::action::Action;

#[derive(Accounts)]
#[instruction(wallet_id: [u8; 32])]
pub struct CloseWallet<'info> {
    /// Must already exist: a wallet never used has no state to close. Its
    /// rent goes back to the relayer, the fee payer that advanced it.
    #[account(
        mut,
        seeds = [WALLET_SEED, wallet_id.as_ref()],
        bump = wallet.state_bump,
        close = relayer,
    )]
    pub wallet: Account<'info, SmartWallet>,

    #[account(
        mut,
        seeds = [VAULT_SEED, wallet_id.as_ref()],
        bump = wallet.vault_bump,
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

impl<'info> CloseWallet<'info> {
    /// Everything the vault holds goes to `to`, but the relayer's refund,
    /// then the state closes. Nothing of the wallet stays on-chain: the
    /// same signature can never pass again.
    pub fn close(&mut self, authorization: Authorization, relayer_fee: u64) -> Result<()> {
        let action = Action::CloseWallet {
            to: self.to.key().to_bytes(),
        };
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

        // Capped by the balance too, unlike any other action: an emptied
        // vault can still close, the state's rent pays the relayer anyway.
        let balance = self.vault.lamports();
        let refund = relayer_fee.min(authorization.max_relayer_fee).min(balance);

        transfer_from_vault(
            &self.wallet,
            &self.vault,
            self.to.to_account_info(),
            &self.system_program,
            balance - refund,
        )?;
        transfer_from_vault(
            &self.wallet,
            &self.vault,
            self.relayer.to_account_info(),
            &self.system_program,
            refund,
        )
    }
}
