use anchor_lang::prelude::*;

use crate::precompile::load_secp256r1_payload;

#[derive(Accounts)]
pub struct TransferSol<'info> {
    /// CHECK: pinned to the Instructions sysvar by the address constraint
    #[account(address = solana_instructions_sysvar::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>
}

impl<'info> TransferSol<'info> {
    pub fn transfer(&mut self) -> Result<()> {
        let payload = load_secp256r1_payload(&self.instructions_sysvar)?;
        msg!("pubkey[0]={} message_len={}", payload.pubkey[0], payload.message.len());

        Ok(())
    }
}