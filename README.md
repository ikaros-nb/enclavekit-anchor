# EnclaveKit

Solana smart wallet controlled by an iPhone Secure Enclave P-256 key.

The user signs an action with the enclave key. The program checks the signature through the `secp256r1` precompile and executes the action from the wallet's vault. A relayer (Kora) pays the transaction fee and is refunded from the vault. The active key can move the wallet to another key at once; guardians can rotate it after a timelock.

- `programs/enclavekit`: the Anchor program.
- `crates/enclavekit-encoding`: action and preimage encoding shared with the Swift SDK. No Solana dependency.
- `crates/gen-vectors`: writes the conformance vectors in `vectors/`.

## On devnet

Program: [`dG4h3aizVEW1bKjzkGsfk6zqcfa2MVn2DjavPniesSY`](https://explorer.solana.com/address/dG4h3aizVEW1bKjzkGsfk6zqcfa2MVn2DjavPniesSY?cluster=devnet)

The [Program IDL tab](https://explorer.solana.com/address/dG4h3aizVEW1bKjzkGsfk6zqcfa2MVn2DjavPniesSY/idl?cluster=devnet) lists the instructions, accounts, errors and constants. The devnet build is compiled with the `devnet` feature, which shortens the rotation delay from 72 hours to 60 seconds: the IDL constant `ROTATION_DELAY = 60` confirms which build is deployed.

## Instructions

| Instruction | Signer | Effect |
|---|---|---|
| `transfer_sol` | active key | Sends lamports from the vault. Creates the wallet on first use. |
| `sweep_vault` | active key | Sends the whole vault, read at execution, and leaves it at 0. The wallet stays, guardians included. Creates the wallet on first use. |
| `set_guardians` | active key | Replaces the 3 guardian slots. Clears any pending rotation. |
| `propose_rotation` | active key or guardian | Active key: swaps the key immediately. Guardian: opens a timelocked proposal. |
| `cancel_rotation` | active key | Drops the pending proposal. |
| `confirm_rotation` | anyone | Applies the proposal once the delay has passed and before the window closes. |
| `close_wallet` | active key | Sends the whole vault, then closes the wallet's state. Its rent goes back to the relayer, which advanced it. |

Every signed instruction carries `wallet_id`, `nonce`, `expires_at` and `max_relayer_fee`, and is preceded in the transaction by the `secp256r1` precompile instruction.

The relayer's refund comes from the vault and never exceeds `max_relayer_fee`. `transfer_sol` refuses an amount the vault cannot cover together with `max_relayer_fee` and its own rent-exempt minimum: only `sweep_vault` and `close_wallet` empty it. `close_wallet` also caps the refund at the vault's balance, so an emptied wallet can still close.

## Events

Every instruction emits its event through a self-CPI (`emit_cpi!`). The event lands in the transaction's inner instructions, which RPCs keep in full where they may truncate logs. `wallet_id` comes first in each, for an indexer to filter on.

| Event | Emitted by | Fields after `wallet_id` |
|---|---|---|
| `WalletCreated` | The wallet's first action, before that action's own event | `key`: the key that made the wallet, whose SHA-256 is `wallet_id` |
| `SolTransferred` | `transfer_sol` | `to`, `lamports`, `relayer_fee` |
| `VaultSwept` | `sweep_vault` | `to`, `lamports` read at execution, `relayer_fee` |
| `WalletClosed` | `close_wallet` | Same as `VaultSwept`. The state's rent goes to the relayer on top of `relayer_fee`. |
| `GuardiansSet` | `set_guardians` | `guardians`: the 3 slots, as stored |
| `RotationProposed` | `propose_rotation` signed by a guardian | `new_key`, `guardian`, `opens_at` |
| `RotationCancelled` | `cancel_rotation` | `new_key` of the dropped proposal |
| `KeyRotated` | `propose_rotation` signed by the active key, `confirm_rotation` | `new_key`, `recovery`: `true` for a guardian's proposal confirmed |

`GuardiansSet` and `KeyRotated` also end a pending rotation, without a `RotationCancelled`.

Every instruction takes two more accounts, last: the event authority, a PDA of the seed `__event_authority` (`379q2cQ1cdxigVA1Cs27XxcBKiiNExU2RQGCCNcxYJMW`), then the program itself. To read an event, look for an inner instruction to the program whose data starts with Anchor's event tag `e445a52e51cb9a1d`, followed by the event's discriminator from the IDL, then its borsh fields.

## Build, test, deploy

```bash
anchor build                          # default build, 72 h rotation delay
cargo test -p enclavekit --tests      # LiteSVM tests, run against the .so from the build above
cargo test -p enclavekit-encoding     # encoding crate

anchor build -- --features devnet     # devnet build, 60 s rotation delay
anchor deploy --provider.cluster devnet --no-idl
anchor idl upgrade -f target/idl/enclavekit.json dG4h3aizVEW1bKjzkGsfk6zqcfa2MVn2DjavPniesSY --provider.cluster devnet
```

Tests read the rotation constants from the crate they are compiled with, so always run them against a `.so` built with the same features. Never run `anchor build` and `cargo test` at the same time.

`anchor deploy` uploads the IDL by default. The IDL is already on devnet: `--no-idl` leaves it to `anchor idl upgrade`, so each step fails on its own. A larger binary grows the program account during the deploy, at the deployer's cost.

## Conformance vectors

`vectors/` holds what any SDK must reproduce byte for byte, generated from the Rust encoding with a fixed test key:

| File | Contents |
|---|---|
| `key.json` | Private scalar, compressed public key, `wallet_id`, program id, the two PDAs and the event authority, with their bumps. |
| `actions.json` | For each implemented `Action`: fields, borsh, full preimage, low-S signature and the complete `secp256r1` instruction data. |
| `high_s.json` | One signature in high-S and low-S form. |
| `transaction.json` | The `transfer_sol` case wrapped in the unsigned transaction handed to Kora: program instruction, message bytes and base64. |
| `instructions.json` | The program instruction of every case of `actions.json` (accounts, the two event accounts included, discriminator, data), plus `confirm_rotation`, which no enclave signs. |
| `state.json` | The state account's data, encoded by Anchor, with the offset of every field: a new wallet, and a wallet with guardians and a pending rotation. |

```bash
cargo run -p gen-vectors      # regenerate after any change to the encoding
cargo test -p gen-vectors     # fails when the committed vectors are stale
```

## Relayer

`kora/` holds the Kora config: allowed programs, fee payer policy, free pricing. The signer is a devnet keypair passed through the `KORA_PRIVATE_KEY` environment variable.

```bash
cargo install kora-cli@2.0.5
export KORA_PRIVATE_KEY=$HOME/.config/solana/kora-fee-payer.json

kora --config kora/kora.toml config validate
kora --config kora/kora.toml --rpc-url https://api.devnet.solana.com rpc start --signers-config kora/signers.toml
```

With Kora running, send one `transfer_sol` on devnet through it. The vault is funded from the Solana CLI wallet:

```bash
cargo run -p enclavekit --example kora_transfer_sol
```
