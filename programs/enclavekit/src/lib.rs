pub mod authorization;
pub mod constants;
pub mod error;
pub mod events;
pub mod instructions;
pub mod precompile;
pub mod state;

use anchor_lang::prelude::*;

use authorization::Authorization;
pub use constants::*;
use events::WalletCreated;
pub use instructions::*;
pub use state::*;

declare_id!("dG4h3aizVEW1bKjzkGsfk6zqcfa2MVn2DjavPniesSY");

// `emit_cpi!` needs `ctx` in scope: each method returns its event, the
// handler emits it. A wallet's first action emits `WalletCreated` before.
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
        let created = ctx.accounts.wallet.is_new();
        let event = ctx
            .accounts
            .transfer(authorization, lamports, relayer_fee, &ctx.bumps)?;
        if created {
            emit_cpi!(WalletCreated {
                wallet_id,
                key: ctx.accounts.wallet.active_key,
            });
        }
        emit_cpi!(event);
        Ok(())
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
        let created = ctx.accounts.wallet.is_new();
        let event =
            ctx.accounts
                .set_guardians(authorization, guardians, relayer_fee, &ctx.bumps)?;
        if created {
            emit_cpi!(WalletCreated {
                wallet_id,
                key: ctx.accounts.wallet.active_key,
            });
        }
        emit_cpi!(event);
        Ok(())
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
        let event = ctx.accounts.cancel(authorization, relayer_fee)?;
        emit_cpi!(event);
        Ok(())
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
        match ctx.accounts.propose(authorization, new_key, relayer_fee)? {
            Proposal::Rotated(event) => emit_cpi!(event),
            Proposal::Pending(event) => emit_cpi!(event),
        }
        Ok(())
    }

    pub fn confirm_rotation(ctx: Context<ConfirmRotation>, _wallet_id: [u8; 32]) -> Result<()> {
        let event = ctx.accounts.confirm()?;
        emit_cpi!(event);
        Ok(())
    }

    pub fn sweep_vault(
        ctx: Context<SweepVault>,
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
        let created = ctx.accounts.wallet.is_new();
        let event = ctx.accounts.sweep(authorization, relayer_fee, &ctx.bumps)?;
        if created {
            emit_cpi!(WalletCreated {
                wallet_id,
                key: ctx.accounts.wallet.active_key,
            });
        }
        emit_cpi!(event);
        Ok(())
    }

    pub fn close_wallet(
        ctx: Context<CloseWallet>,
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
        let event = ctx.accounts.close(authorization, relayer_fee)?;
        emit_cpi!(event);
        Ok(())
    }
}
