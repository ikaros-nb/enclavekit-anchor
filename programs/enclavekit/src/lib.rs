pub mod authorization;
pub mod constants;
pub mod error;
pub mod instructions;
pub mod precompile;
pub mod state;

use anchor_lang::prelude::*;

use authorization::Authorization;
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
        let authorization = Authorization {
            wallet_id,
            nonce,
            expires_at,
            max_relayer_fee,
        };
        ctx.accounts
            .transfer(authorization, lamports, relayer_fee, &ctx.bumps)
    }

    pub fn set_guardians(
        ctx: Context<SetGuardians>,
        wallet_id: [u8; 32],
        nonce: u64,
        expires_at: i64,
        max_relayer_fee: u64,
        guardians: [Guardian; MAX_GUARDIANS],
        relayer_fee: u64,
    ) -> Result<()> {
        let authorization = Authorization {
            wallet_id,
            nonce,
            expires_at,
            max_relayer_fee,
        };
        ctx.accounts
            .set_guardians(authorization, guardians, relayer_fee, &ctx.bumps)
    }

    pub fn cancel_rotation(
        ctx: Context<CancelRotation>,
        wallet_id: [u8; 32],
        nonce: u64,
        expires_at: i64,
        max_relayer_fee: u64,
        relayer_fee: u64,
    ) -> Result<()> {
        let authorization = Authorization {
            wallet_id,
            nonce,
            expires_at,
            max_relayer_fee,
        };
        ctx.accounts.cancel(authorization, relayer_fee)
    }

    pub fn propose_rotation(
        ctx: Context<ProposeRotation>,
        wallet_id: [u8; 32],
        nonce: u64,
        expires_at: i64,
        max_relayer_fee: u64,
        new_key: [u8; COMPRESSED_PUBKEY_LEN],
        relayer_fee: u64,
    ) -> Result<()> {
        let authorization = Authorization {
            wallet_id,
            nonce,
            expires_at,
            max_relayer_fee,
        };
        ctx.accounts.propose(authorization, new_key, relayer_fee)
    }
}
