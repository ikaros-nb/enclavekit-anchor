use anchor_lang::{
    prelude::*,
    system_program::{Transfer, transfer},
};
use solana_sha256_hasher::hash;

use crate::{
    COMPRESSED_PUBKEY_LEN, Guardian, MAX_GUARDIANS, SmartWallet, VAULT_SEED, WALLET_SEED, error::EnclaveKitError, precompile::load_secp256r1_payload,
};

use enclavekit_encoding::{action::Action, preimage::Preimage};

#[derive(Accounts)]
#[instruction(wallet_id: [u8; 32])]
pub struct TransferSol<'info> {
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

impl<'info> TransferSol<'info> {
    pub fn transfer(
        &mut self,
        wallet_id: [u8; 32],
        nonce: u64,
        expires_at: i64,
        max_relayer_fee: u64,
        lamports: u64,
        relayer_fee: u64,
        bumps: &TransferSolBumps,
    ) -> Result<()> {
        let payload = load_secp256r1_payload(&self.instructions_sysvar)?;
        msg!("pubkey[0]={} message_len={}", payload.pubkey[0], payload.message.len());

        if self.wallet.active_key == [0u8; COMPRESSED_PUBKEY_LEN] {
            require!(
                hash(&payload.pubkey).to_bytes() == wallet_id,
                EnclaveKitError::WalletIdMismatch
            );

            self.wallet.set_inner(SmartWallet {
                wallet_id,
                active_key: payload.pubkey,
                nonce: 0,
                attested: false,
                rotation: None,
                guardians: [Guardian::None; MAX_GUARDIANS],
                state_bump: bumps.wallet,
                vault_bump: bumps.vault,
            });
        } else {
            require!(payload.pubkey == self.wallet.active_key, EnclaveKitError::KeyMismatch);
        }

        require!(nonce == self.wallet.nonce, EnclaveKitError::NonceMismatch);
        require!(expires_at > Clock::get()?.unix_timestamp, EnclaveKitError::AuthorizationExpired);

        let action = Action::TransferSol { to: self.to.key().to_bytes(), lamports };
        let expected = Preimage {
            program_id: crate::ID.to_bytes(),
            wallet_id, nonce, expires_at, max_relayer_fee,
            action: &action,
        };
        require!(expected.to_bytes() == payload.message, EnclaveKitError::PreimageMismatch);

        self.wallet.nonce = self
            .wallet
            .nonce
            .checked_add(1)
            .ok_or(ProgramError::ArithmeticOverflow)?;

        let seeds = &[
            &VAULT_SEED[..],
            wallet_id.as_ref(),
            &[self.wallet.vault_bump]
        ];
        let signer_seeds = &[&seeds[..]];
        
        transfer(
            CpiContext::new_with_signer(
                self.system_program.key(),
                Transfer {
                    from: self.vault.to_account_info(),
                    to: self.to.to_account_info(),
                },
                signer_seeds
            ),
            lamports,
        )?;

        transfer(
            CpiContext::new_with_signer(
                self.system_program.key(),
                Transfer {
                    from: self.vault.to_account_info(),
                    to: self.relayer.to_account_info(),
                },
                signer_seeds
            ),
            relayer_fee.min(max_relayer_fee),
        )?;
        Ok(())
    }
}
