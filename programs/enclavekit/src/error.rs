use anchor_lang::prelude::*;

#[error_code]
pub enum EnclaveKitError {
    #[msg("The instruction before this one is not the secp256r1 precompile")]
    PrecompileProgramMismatch,
    #[msg("The precompile instruction must not reference any account")]
    PrecompileUnexpectedAccounts,
    #[msg("The precompile instruction data is too short")]
    PrecompileDataTooShort,
    #[msg("The precompile instruction must carry exactly one signature")]
    PrecompileSignatureCountMismatch,
    #[msg("The precompile offsets do not match the expected layout")]
    PrecompileLayoutMismatch,
    #[msg("The precompile message size does not match the instruction data length")]
    PrecompileMessageSizeMismatch,
    #[msg("SHA-256 of the signing key does not match wallet_id on first use")]
    WalletIdMismatch,
    #[msg("The signing key is not the wallet's active key")]
    KeyMismatch,
    #[msg("The nonce does not match the wallet counter")]
    NonceMismatch,
    #[msg("The signed authorization has expired")]
    AuthorizationExpired,
    #[msg("The signed message does not match the instruction arguments")]
    PreimageMismatch,
    #[msg("WebAuthn guardians are not supported in v1")]
    WebAuthnGuardianUnsupported,
}
