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
}
