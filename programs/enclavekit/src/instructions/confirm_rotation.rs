use anchor_lang::prelude::*;

use crate::{error::EnclaveKitError, SmartWallet, WALLET_SEED};

/// Permissionless: no precompile, no signed preimage, no nonce, no refund.
#[derive(Accounts)]
#[instruction(wallet_id: [u8; 32])]
pub struct ConfirmRotation<'info> {
    #[account(
        mut,
        seeds = [WALLET_SEED, wallet_id.as_ref()],
        bump = wallet.state_bump,
    )]
    pub wallet: Account<'info, SmartWallet>,
}

impl<'info> ConfirmRotation<'info> {
    pub fn confirm(&mut self) -> Result<()> {
        let pending = self
            .wallet
            .rotation
            .as_ref()
            .ok_or(EnclaveKitError::NoPendingRotation)?;

        let now = Clock::get()?.unix_timestamp;
        require!(now >= pending.opens_at(), EnclaveKitError::RotationTooEarly);
        require!(!pending.is_expired(now), EnclaveKitError::RotationExpired);

        self.wallet.active_key = pending.new_key;
        self.wallet.attested = false;
        self.wallet.rotation = None;
        Ok(())
    }
}
