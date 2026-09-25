# EnclaveKit

Solana smart wallet controlled by an iPhone Secure Enclave P-256 key.

The user signs an action with the enclave key. The program checks the signature through the `secp256r1` precompile and executes the action from the wallet's vault. A relayer (Kora) pays the transaction fee and is refunded from the vault. Guardians can rotate the key after a timelock.

- `programs/enclavekit`: the Anchor program.
- `crates/enclavekit-encoding`: action and preimage encoding shared with the Swift SDK. No Solana dependency.

## On devnet

Program: [`dG4h3aizVEW1bKjzkGsfk6zqcfa2MVn2DjavPniesSY`](https://explorer.solana.com/address/dG4h3aizVEW1bKjzkGsfk6zqcfa2MVn2DjavPniesSY?cluster=devnet)

The [Program IDL tab](https://explorer.solana.com/address/dG4h3aizVEW1bKjzkGsfk6zqcfa2MVn2DjavPniesSY/idl?cluster=devnet) lists the instructions, accounts, errors and constants. The devnet build is compiled with the `devnet` feature, which shortens the rotation delay from 72 hours to 60 seconds: the IDL constant `ROTATION_DELAY = 60` confirms which build is deployed.

## Instructions

| Instruction | Signer | Effect |
|---|---|---|
| `transfer_sol` | active key | Sends lamports from the vault. Creates the wallet on first use. |
| `set_guardians` | active key | Replaces the 3 guardian slots. Clears any pending rotation. |
| `propose_rotation` | active key or guardian | Active key: swaps the key immediately. Guardian: opens a timelocked proposal. |
| `cancel_rotation` | active key | Drops the pending proposal. |
| `confirm_rotation` | anyone | Applies the proposal once the delay has passed and before the window closes. |

Every signed instruction carries `wallet_id`, `nonce`, `expires_at` and `max_relayer_fee`, and is preceded in the transaction by the `secp256r1` precompile instruction.

## Build, test, deploy

```bash
anchor build                          # default build, 72 h rotation delay
cargo test -p enclavekit --tests      # LiteSVM tests, run against the .so from the build above
cargo test -p enclavekit-encoding     # encoding crate

anchor build -- --features devnet     # devnet build, 60 s rotation delay
anchor deploy --provider.cluster devnet
anchor idl upgrade -f target/idl/enclavekit.json dG4h3aizVEW1bKjzkGsfk6zqcfa2MVn2DjavPniesSY --provider.cluster devnet
```

Tests read the rotation constants from the crate they are compiled with, so always run them against a `.so` built with the same features. Never run `anchor build` and `cargo test` at the same time.
