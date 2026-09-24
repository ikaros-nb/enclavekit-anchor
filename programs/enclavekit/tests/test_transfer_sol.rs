mod common;

use anchor_lang::prelude::Pubkey;
use common::{vault_pda, wallet_pda, EnclaveKey, Env, TransferSolRequest};
use litesvm::types::TransactionMetadata;
use solana_signer::Signer;

const VAULT_FUNDING: u64 = 1_000_000_000;
const LAMPORTS: u64 = 100_000_000;
const MAX_RELAYER_FEE: u64 = 100_000;
const RELAYER_FEE: u64 = 50_000;

struct Scenario {
    env: Env,
    key: EnclaveKey,
    request: TransferSolRequest,
}

impl Scenario {
    fn new() -> Self {
        let mut env = Env::new();
        let key = EnclaveKey::from_seed([7u8; 32]);
        let wallet_id = key.wallet_id();
        env.svm.airdrop(&vault_pda(&wallet_id), VAULT_FUNDING).unwrap();

        let request = TransferSolRequest {
            wallet_id,
            to: Pubkey::new_unique(),
            lamports: LAMPORTS,
            nonce: 0,
            expires_at: env.unix_timestamp() + 60,
            max_relayer_fee: MAX_RELAYER_FEE,
            relayer_fee: RELAYER_FEE,
        };
        Self { env, key, request }
    }

    fn relayer(&self) -> Pubkey {
        self.env.payer.pubkey()
    }

    fn send(&mut self, request: &TransferSolRequest) -> TransactionMetadata {
        let instructions = request.sign(&self.key, &self.relayer());
        self.env
            .send(&instructions)
            .unwrap_or_else(|failed| panic!("{:?}\n{:#?}", failed.err, failed.meta.logs))
    }
}

#[test]
fn first_action_creates_the_wallet_pays_and_refunds() {
    let mut scenario = Scenario::new();
    let request = scenario.request.clone();
    let relayer = scenario.relayer();
    let relayer_before = scenario.env.balance(&relayer);

    let meta = scenario.send(&request);

    let wallet = scenario
        .env
        .wallet(&request.wallet_id)
        .expect("first action creates the state PDA");
    assert_eq!(wallet.wallet_id, request.wallet_id);
    assert_eq!(wallet.active_key, scenario.key.compressed_pubkey());
    assert_eq!(wallet.nonce, 1);
    assert!(!wallet.attested);
    assert!(wallet.rotation.is_none());

    assert_eq!(scenario.env.balance(&request.to), LAMPORTS);
    assert_eq!(
        scenario.env.balance(&vault_pda(&request.wallet_id)),
        VAULT_FUNDING - LAMPORTS - RELAYER_FEE
    );

    // The relayer paid the transaction fee and the state rent, then got its
    // requested fee back from the vault.
    let rent = scenario.env.balance(&wallet_pda(&request.wallet_id));
    assert_eq!(
        scenario.env.balance(&relayer),
        relayer_before - meta.fee - rent + RELAYER_FEE
    );
}

#[test]
fn second_action_uses_the_next_nonce() {
    let mut scenario = Scenario::new();
    let first = scenario.request.clone();
    scenario.send(&first);

    let second = TransferSolRequest { nonce: 1, ..first.clone() };
    scenario.send(&second);

    let wallet = scenario.env.wallet(&first.wallet_id).unwrap();
    assert_eq!(wallet.nonce, 2);
    assert_eq!(scenario.env.balance(&first.to), 2 * LAMPORTS);
    assert_eq!(
        scenario.env.balance(&vault_pda(&first.wallet_id)),
        VAULT_FUNDING - 2 * (LAMPORTS + RELAYER_FEE)
    );
}
