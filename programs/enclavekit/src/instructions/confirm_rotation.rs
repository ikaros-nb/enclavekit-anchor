use anchor_lang::prelude::*;

use crate::{error::EnclaveKitError, events::KeyRotated, RotationSlot, SmartWallet, WALLET_SEED};

/// Permissionless: no precompile, no signed preimage, no nonce, no refund.
#[event_cpi]
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
    pub fn confirm(&mut self) -> Result<KeyRotated> {
        let pending = self
            .wallet
            .rotation
            .get()
            .ok_or(EnclaveKitError::NoPendingRotation)?;

        let now = Clock::get()?.unix_timestamp;
        require!(now >= pending.opens_at(), EnclaveKitError::RotationTooEarly);
        require!(!pending.is_expired(now), EnclaveKitError::RotationExpired);

        let new_key = pending.new_key;
        self.wallet.active_key = new_key;
        self.wallet.attested = false;
        self.wallet.rotation = RotationSlot::EMPTY;

        Ok(KeyRotated {
            wallet_id: self.wallet.wallet_id,
            new_key,
            recovery: true,
        })
    }
}
