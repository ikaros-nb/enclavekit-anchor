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

    pub fn transfer_sol(ctx: Context<TransferSol>) -> Result<()> {
        ctx.accounts.transfer()
    }
}
