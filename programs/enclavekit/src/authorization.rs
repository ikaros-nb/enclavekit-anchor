use anchor_lang::{
    prelude::*,
    system_program::{transfer, Transfer},
};
use solana_sha256_hasher::hash;

use crate::{
    error::EnclaveKitError, precompile::load_secp256r1_payload, Guardian, SmartWallet,
    COMPRESSED_PUBKEY_LEN, MAX_GUARDIANS, VAULT_SEED,
};

use enclavekit_encoding::{action::Action, preimage::Preimage};

pub struct Authorization {
    pub wallet_id: [u8; 32],
    pub nonce: u64,
    pub expires_at: i64,
    pub max_relayer_fee: u64,
}

pub fn verify_enclave_authorization(
    wallet: &mut SmartWallet,
    instructions_sysvar: &AccountInfo,
    auth: &Authorization,
    action: &Action,
    state_bump: u8,
    vault_bump: u8,
) -> Result<[u8; COMPRESSED_PUBKEY_LEN]> {
    let payload = load_secp256r1_payload(instructions_sysvar)?;

    if wallet.active_key == [0u8; COMPRESSED_PUBKEY_LEN] {
        require!(
            hash(&payload.pubkey).to_bytes() == auth.wallet_id,
            EnclaveKitError::WalletIdMismatch
        );

        *wallet = SmartWallet {
            wallet_id: auth.wallet_id,
            active_key: payload.pubkey,
            nonce: 0,
            attested: false,
            rotation: None,
            guardians: [Guardian::None; MAX_GUARDIANS],
            state_bump,
            vault_bump,
        };
    }

    require!(auth.nonce == wallet.nonce, EnclaveKitError::NonceMismatch);
    require!(
        auth.expires_at > Clock::get()?.unix_timestamp,
        EnclaveKitError::AuthorizationExpired
    );

    let expected = Preimage {
        program_id: crate::ID.to_bytes(),
        wallet_id: auth.wallet_id,
        nonce: auth.nonce,
        expires_at: auth.expires_at,
        max_relayer_fee: auth.max_relayer_fee,
        action,
    };
    require!(
        expected.to_bytes() == payload.message,
        EnclaveKitError::PreimageMismatch
    );

    wallet.nonce = wallet
        .nonce
        .checked_add(1)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    Ok(payload.pubkey)
}

/// For instructions only the active key may authorise.
pub fn require_active_key(
    wallet: &SmartWallet,
    signer: &[u8; COMPRESSED_PUBKEY_LEN],
) -> Result<()> {
    require!(*signer == wallet.active_key, EnclaveKitError::KeyMismatch);
    Ok(())
}

/// Moves lamports out of the vault, signed with its seeds.
pub fn transfer_from_vault<'info>(
    wallet: &SmartWallet,
    vault: &SystemAccount<'info>,
    to: AccountInfo<'info>,
    system_program: &Program<'info, System>,
    lamports: u64,
) -> Result<()> {
    let seeds = &[VAULT_SEED, wallet.wallet_id.as_ref(), &[wallet.vault_bump]];
    let signer_seeds = &[&seeds[..]];

    transfer(
        CpiContext::new_with_signer(
            system_program.key(),
            Transfer {
                from: vault.to_account_info(),
                to,
            },
            signer_seeds,
        ),
        lamports,
    )
}

/// Pays the relayer back from the vault, never more than the enclave signed.
pub fn refund_relayer<'info>(
    wallet: &SmartWallet,
    vault: &SystemAccount<'info>,
    relayer: &Signer<'info>,
    system_program: &Program<'info, System>,
    relayer_fee: u64,
    max_relayer_fee: u64,
) -> Result<()> {
    transfer_from_vault(
        wallet,
        vault,
        relayer.to_account_info(),
        system_program,
        relayer_fee.min(max_relayer_fee),
    )
}
