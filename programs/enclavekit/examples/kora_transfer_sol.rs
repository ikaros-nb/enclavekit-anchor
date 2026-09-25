//! One `transfer_sol` on devnet, paid by a local Kora relayer.
//!
//! Kora's fee payer is the `relayer` account of the instruction: writable,
//! rent payer of the state on first use, refund destination. The run proves
//! Kora accepts to sign such a transaction.
//!
//! Needs a Kora node (`KORA_URL`, default http://127.0.0.1:8080) and a
//! funded devnet keypair (`FUNDER_KEYPAIR`, default
//! ~/.config/solana/wallet-a.json) to top up the vault.
//!
//! ```bash
//! cargo run -p enclavekit --example kora_transfer_sol
//! ```
//!
//! A fresh enclave key is drawn on every run. Set `ENCLAVE_SEED` (64 hex
//! chars) to reuse a wallet: the nonce is then read on-chain. The unsigned
//! transaction handed to Kora is written to `target/kora_transfer_sol.b64`,
//! the reference the Swift SDK must reproduce byte for byte.

#[path = "../tests/common/requests.rs"]
mod requests;

use std::{
    error::Error,
    fs,
    io::Read,
    str::FromStr,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anchor_lang::prelude::Pubkey;
use anchor_lang::{AccountDeserialize, Discriminator, Space};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use enclavekit::SmartWallet;
use requests::{vault_pda, wallet_pda, EnclaveKey, EnclaveRequest, TransferSolRequest};
use serde_json::{json, Value};
use solana_hash::Hash;
use solana_keypair::{read_keypair_file, Keypair};
use solana_message::{Message, VersionedMessage};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

const KORA_URL: &str = "http://127.0.0.1:8080";
const RPC_URL: &str = "https://api.devnet.solana.com";
const UNSIGNED_TX_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/kora_transfer_sol.b64"
);

/// What the wallet sends to `to`.
const LAMPORTS: u64 = 10_000_000;
/// Left in the vault after the run, above the rent-exempt minimum of an empty account.
const VAULT_RESERVE: u64 = 5_000_000;
/// 5 000 lamports per signature, and the runtime counts the secp256r1 one
/// the precompile verifies alongside the fee payer's Ed25519 signature.
const TRANSACTION_FEE: u64 = 10_000;
const AUTHORIZATION_TTL: i64 = 120;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn main() -> Result<()> {
    let kora = JsonRpc::new(env_or("KORA_URL", KORA_URL));
    let rpc = JsonRpc::new(env_or("RPC_URL", RPC_URL));
    let home = std::env::var("HOME")?;
    let funder = read_keypair_file(env_or(
        "FUNDER_KEYPAIR",
        &format!("{home}/.config/solana/wallet-a.json"),
    ))?;

    let key = enclave_key()?;
    let wallet_id = key.wallet_id();
    let wallet = wallet_pda(&wallet_id);
    let vault = vault_pda(&wallet_id);
    let to = Keypair::new().pubkey();
    println!("wallet id  {}", hex(&wallet_id));
    println!("state      {wallet}");
    println!("vault      {vault}");
    println!("to         {to}");

    // 1. The relayer Kora will sign with: the `relayer` account of the instruction.
    let relayer = Pubkey::from_str(str_field(
        &kora.call("getPayerSigner", json!([]))?,
        "signer_address",
    )?)?;
    println!("relayer    {relayer}");

    // 2. What the relayer advances: the transaction fee, plus the rent of the
    //    state when this is the wallet's first use. The vault pays it back.
    let nonce = wallet_nonce(&rpc, &wallet)?;
    let rent = match nonce {
        Some(_) => 0,
        None => {
            let space = SmartWallet::DISCRIMINATOR.len() + SmartWallet::INIT_SPACE;
            rent_exempt_minimum(&rpc, space)?
        }
    };
    let relayer_fee = rent + TRANSACTION_FEE;
    let nonce = nonce.unwrap_or(0);
    println!("nonce      {nonce}");
    println!("relayer fee {relayer_fee} lamports (rent {rent} + fee {TRANSACTION_FEE})");

    // 3. Fund the vault from the CLI wallet, in a plain transaction outside Kora.
    let needed = LAMPORTS + relayer_fee + VAULT_RESERVE;
    let held = balance(&rpc, &vault)?;
    if held < needed {
        let signature = fund(&rpc, &funder, &vault, needed - held)?;
        println!("vault funded {} lamports: {signature}", needed - held);
    }

    // 4. The enclave signs; the transaction carries no Ed25519 signature yet.
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let request = TransferSolRequest {
        wallet_id,
        to,
        lamports: LAMPORTS,
        nonce,
        expires_at: now + AUTHORIZATION_TTL,
        max_relayer_fee: relayer_fee,
        relayer_fee,
    };
    let instructions = request.sign(&key, &relayer);
    let blockhash = Hash::from_str(str_field(
        &kora.call("getBlockhash", json!([]))?,
        "blockhash",
    )?)?;
    let message = Message::new_with_blockhash(&instructions, Some(&relayer), &blockhash);
    let unsigned = VersionedTransaction {
        signatures: vec![Default::default()],
        message: VersionedMessage::Legacy(message),
    };
    let unsigned_b64 = BASE64.encode(bincode::serialize(&unsigned)?);
    fs::write(UNSIGNED_TX_PATH, &unsigned_b64)?;
    println!("unsigned transaction written to {UNSIGNED_TX_PATH}");

    // 5. Kora validates, simulates, signs as fee payer and sends.
    let relayer_before = balance(&rpc, &relayer)?;
    let sent = kora.call(
        "signAndSendTransaction",
        json!({ "transaction": unsigned_b64 }),
    )?;
    let signature = str_field(&sent, "signature")?;
    println!("sent       {signature}");
    confirm(&rpc, signature)?;
    println!("confirmed  https://explorer.solana.com/tx/{signature}?cluster=devnet");

    // 6. The destination got the lamports; the relayer is whole again.
    let relayer_after = balance(&rpc, &relayer)?;
    println!("to balance {} lamports", balance(&rpc, &to)?);
    println!(
        "relayer    {:+} lamports over the transaction",
        relayer_after as i128 - relayer_before as i128
    );
    Ok(())
}

/// Seed from `ENCLAVE_SEED`, otherwise 32 random bytes: a new wallet.
fn enclave_key() -> Result<EnclaveKey> {
    let mut seed = [0u8; 32];
    match std::env::var("ENCLAVE_SEED") {
        Ok(hex) => {
            if hex.len() != 64 {
                return Err("ENCLAVE_SEED must be 64 hex chars".into());
            }
            for (i, byte) in seed.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)?;
            }
        }
        Err(_) => fs::File::open("/dev/urandom")?.read_exact(&mut seed)?,
    }
    Ok(EnclaveKey::from_seed(seed))
}

/// `nonce` of the wallet, `None` when the state account does not exist yet.
fn wallet_nonce(rpc: &JsonRpc, wallet: &Pubkey) -> Result<Option<u64>> {
    let info = rpc.call(
        "getAccountInfo",
        json!([wallet.to_string(), { "encoding": "base64", "commitment": "confirmed" }]),
    )?;
    if info["value"].is_null() {
        return Ok(None);
    }
    let data = BASE64.decode(str_field(&info["value"]["data"], "0")?)?;
    let state = SmartWallet::try_deserialize(&mut data.as_slice())?;
    Ok(Some(state.nonce))
}

fn rent_exempt_minimum(rpc: &JsonRpc, space: usize) -> Result<u64> {
    u64_of(&rpc.call("getMinimumBalanceForRentExemption", json!([space]))?)
}

fn balance(rpc: &JsonRpc, address: &Pubkey) -> Result<u64> {
    u64_of(
        &rpc.call(
            "getBalance",
            json!([address.to_string(), { "commitment": "confirmed" }]),
        )?["value"],
    )
}

/// System transfer signed by `funder`, confirmed before returning.
fn fund(rpc: &JsonRpc, funder: &Keypair, to: &Pubkey, lamports: u64) -> Result<String> {
    let blockhash = rpc.call("getLatestBlockhash", json!([{ "commitment": "confirmed" }]))?;
    let blockhash = Hash::from_str(str_field(&blockhash["value"], "blockhash")?)?;
    let instruction =
        solana_system_interface::instruction::transfer(&funder.pubkey(), to, lamports);
    let message = Message::new_with_blockhash(&[instruction], Some(&funder.pubkey()), &blockhash);
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(message), &[funder])?;
    let sent = rpc.call(
        "sendTransaction",
        json!([BASE64.encode(bincode::serialize(&tx)?), { "encoding": "base64", "preflightCommitment": "confirmed" }]),
    )?;
    let signature = sent
        .as_str()
        .ok_or("sendTransaction: no signature")?
        .to_string();
    confirm(rpc, &signature)?;
    Ok(signature)
}

/// Polls until the transaction is confirmed, fails if it errored or vanished.
fn confirm(rpc: &JsonRpc, signature: &str) -> Result<()> {
    for _ in 0..60 {
        let statuses = rpc.call(
            "getSignatureStatuses",
            json!([[signature], { "searchTransactionHistory": true }]),
        )?;
        let status = &statuses["value"][0];
        if !status.is_null() {
            if !status["err"].is_null() {
                return Err(format!("transaction {signature} failed: {}", status["err"]).into());
            }
            if matches!(
                status["confirmationStatus"].as_str(),
                Some("confirmed" | "finalized")
            ) {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_secs(1));
    }
    Err(format!("transaction {signature} not confirmed after 60 s").into())
}

struct JsonRpc {
    url: String,
}

impl JsonRpc {
    fn new(url: String) -> Self {
        Self { url }
    }

    /// One JSON-RPC 2.0 call; a JSON-RPC error becomes an `Err`.
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let mut response = ureq::post(&self.url).send_json(&body)?;
        let reply: Value = response.body_mut().read_json()?;
        if let Some(error) = reply.get("error") {
            return Err(format!("{method}: {error}").into());
        }
        reply
            .get("result")
            .cloned()
            .ok_or_else(|| format!("{method}: no result in {reply}").into())
    }
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn str_field<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    let inner = match field.parse::<usize>() {
        Ok(index) => &value[index],
        Err(_) => &value[field],
    };
    inner
        .as_str()
        .ok_or_else(|| format!("missing string `{field}` in {value}").into())
}

fn u64_of(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .ok_or_else(|| format!("expected a number, got {value}").into())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
