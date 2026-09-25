pub mod authorization;
pub mod constants;
pub mod error;
pub mod instructions;
pub mod precompile;
pub mod state;

use anchor_lang::prelude::*;

pub use constants::*;
pub use instructions::*;
pub use state::*;

declare_id!("dG4h3aizVEW1bKjzkGsfk6zqcfa2MVn2DjavPniesSY");

#[program]
pub mod enclavekit {
    use super::*;

    pub fn transfer_sol(
        ctx: Context<TransferSol>,
        wallet_id: [u8; 32],
        nonce: u64,
        expires_at: i64,
        max_relayer_fee: u64,
        lamports: u64,
        relayer_fee: u64,
    ) -> Result<()> {
        ctx.accounts.transfer(
            wallet_id,
            nonce,
            expires_at,
            max_relayer_fee,
            lamports,
            relayer_fee,
            &ctx.bumps,
        )
    }
}
