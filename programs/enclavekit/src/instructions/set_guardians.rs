use anchor_lang::prelude::*;

use crate::{
    authorization::{
        refund_relayer, require_active_key, verify_enclave_authorization, Authorization,
    },
    error::EnclaveKitError,
    Guardian, SmartWallet, MAX_GUARDIANS, VAULT_SEED, WALLET_SEED,
};

use enclavekit_encoding::action::Action;

#[derive(Accounts)]
#[instruction(wallet_id: [u8; 32])]
pub struct SetGuardians<'info> {
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

    #[account(mut)]
    pub relayer: Signer<'info>,

    /// CHECK: pinned to the Instructions sysvar by the address constraint
    #[account(address = solana_instructions_sysvar::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

impl<'info> SetGuardians<'info> {
    pub fn set_guardians(
        &mut self,
        wallet_id: [u8; 32],
        nonce: u64,
        expires_at: i64,
        max_relayer_fee: u64,
        guardians: [Guardian; MAX_GUARDIANS],
        relayer_fee: u64,
        bumps: &SetGuardiansBumps,
    ) -> Result<()> {
        let action = Action::SetGuardians {
            guardians: guardians.map(Into::into),
        };
        let authorization = Authorization {
            wallet_id,
            nonce,
            expires_at,
            max_relayer_fee,
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

        require!(
            !guardians
                .iter()
                .any(|guardian| matches!(guardian, Guardian::WebAuthn(_))),
            EnclaveKitError::WebAuthnGuardianUnsupported
        );

        // The whole list is replaced.
        self.wallet.guardians = guardians;
        self.wallet.rotation = None;

        refund_relayer(
            &self.wallet,
            &self.vault,
            &self.relayer,
            &self.system_program,
            relayer_fee,
            max_relayer_fee,
        )
    }
}
