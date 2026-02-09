use bech32::{self, Bech32, Hrp};
use multiversx_sc::derive_imports::*;
use multiversx_sc::types::{Address, CodeMetadata, ManagedBuffer};
use multiversx_sc_snippets::imports::*;

pub const GATEWAY_URL: &str = "http://localhost:8085";
pub const WASM_PATH: &str = "artifacts/identity-registry.wasm";
pub const VALIDATION_WASM_PATH: &str = "artifacts/validation-registry.wasm";
pub const REPUTATION_WASM_PATH: &str = "artifacts/reputation-registry.wasm";

pub async fn get_simulator_chain_id() -> String {
    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .get(format!("{}/network/config", GATEWAY_URL))
        .send()
        .await
        .expect("Failed to get network config")
        .json()
        .await
        .expect("Failed to parse network config");

    resp["data"]["config"]["erd_chain_id"]
        .as_str()
        .expect("Chain ID not found")
        .to_string()
}

/// Fund an address on the chain simulator using /simulator/set-state.
/// This bypasses the initial wallet balance limits (typically ~10 EGLD).
/// `balance_wei` should be the full balance in wei (e.g. "100000000000000000000000" for 100,000 EGLD).
pub async fn fund_address_on_simulator(address_bech32: &str, balance_wei: &str) {
    let client = reqwest::Client::new();
    let body = serde_json::json!([{
        "address": address_bech32,
        "balance": balance_wei,
        "nonce": 0
    }]);
    let res = client
        .post(format!("{}/simulator/set-state", GATEWAY_URL))
        .json(&body)
        .send()
        .await
        .expect("Failed to set state on simulator");
    assert!(
        res.status().is_success(),
        "set-state failed: {}",
        res.text().await.unwrap_or_default()
    );
}

/// Generate blocks on the chain simulator (needed when broadcasting
/// via external services like relayer/facilitator, since `interactor.tx().run()`
/// auto-generates blocks but HTTP broadcasts don't).
pub async fn generate_blocks_on_simulator(num_blocks: u32) {
    let client = reqwest::Client::new();
    let res = client
        .post(format!(
            "{}/simulator/generate-blocks/{}",
            GATEWAY_URL, num_blocks
        ))
        .send()
        .await
        .expect("Failed to generate blocks on simulator");
    assert!(res.status().is_success(), "generate-blocks failed");
}

use rand::RngCore;

pub fn generate_random_private_key() -> String {
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);
    hex::encode(key)
}

pub fn address_to_bech32(address: &Address) -> String {
    let hrp = Hrp::parse("erd").expect("Invalid HRP");
    bech32::encode::<Bech32>(hrp, address.as_bytes()).expect("Failed to encode address")
}

use base64::{engine::general_purpose, Engine as _};

pub fn create_pem_file(file_path: &str, private_key_hex: &str, _address_bech32: &str) {
    let priv_bytes = hex::decode(private_key_hex).expect("Invalid hex");
    let wallet = Wallet::from_private_key(private_key_hex).expect("Wallet failed");
    let address = wallet.to_address(); // multiversx_chain_core::types::Address
    let pub_bytes = address.as_bytes();

    // We need bech32 for formatting the PEM header/footer correctly if we were using it for calling, but here we just write it.
    let address_bech32 = address.to_bech32("erd").to_string();

    let mut combined = Vec::new(); // 32 priv + 32 pub
    combined.extend_from_slice(&priv_bytes);
    combined.extend_from_slice(pub_bytes);

    let hex_combined = hex::encode(&combined);
    let b64 = general_purpose::STANDARD.encode(hex_combined);

    // Split into lines of 64 chars for standard PEM format
    let chunks: Vec<String> = b64
        .chars()
        .collect::<Vec<char>>()
        .chunks(64)
        .map(|c| c.iter().collect())
        .collect();
    let b64_formatted = chunks.join("\n");

    let pem_content = format!(
        "-----BEGIN PRIVATE KEY for {}-----\n{}\n-----END PRIVATE KEY for {}-----",
        address_bech32, b64_formatted, address_bech32
    );

    std::fs::write(file_path, pem_content).expect("Failed to write PEM");
}

#[type_abi]
#[derive(
    TopEncode, TopDecode, ManagedVecItem, NestedEncode, NestedDecode, Clone, PartialEq, Debug,
)]
pub struct MetadataEntry<M: ManagedTypeApi> {
    pub key: ManagedBuffer<M>,
    pub value: ManagedBuffer<M>,
}

pub struct IdentityRegistryInteractor<'a> {
    pub interactor: &'a mut Interactor,
    pub wallet_address: Address,
    pub contract_address: Address,
}

impl<'a> IdentityRegistryInteractor<'a> {
    pub async fn init(interactor: &'a mut Interactor, wallet_address: Address) -> Self {
        println!("Reading WASM from: {}", WASM_PATH);
        let wasm_bytes = std::fs::read(WASM_PATH).expect("Failed to read WASM file");
        println!("Read WASM size: {}", wasm_bytes.len());

        let code_buf = ManagedBuffer::new_from_bytes(&wasm_bytes);

        interactor.generate_blocks_until_all_activations().await;

        let contract_address = interactor
            .tx()
            .from(&wallet_address)
            .gas(600_000_000)
            .raw_deploy()
            .code(code_buf)
            .code_metadata(CodeMetadata::PAYABLE_BY_SC)
            .returns(ReturnsNewAddress)
            .run()
            .await;

        println!("Deployed Identity Registry at: {}", contract_address);

        Self {
            interactor,
            wallet_address,
            contract_address,
        }
    }

    pub async fn issue_token(&mut self, name: &str, ticker: &str) {
        let name_buf: ManagedBuffer<StaticApi> = ManagedBuffer::new_from_bytes(name.as_bytes());
        let ticker_buf: ManagedBuffer<StaticApi> = ManagedBuffer::new_from_bytes(ticker.as_bytes());

        self.interactor
            .tx()
            .from(&self.wallet_address)
            .to(&self.contract_address)
            .gas(600_000_000)
            .egld(50_000_000_000_000_000u64)
            .raw_call("issue_token")
            .argument(&name_buf)
            .argument(&ticker_buf)
            .run()
            .await;

        println!("Issued Token: {}", ticker);
    }

    pub async fn register_agent(&mut self, name: &str, uri: &str, metadata: Vec<(&str, Vec<u8>)>) {
        let name_buf: ManagedBuffer<StaticApi> = ManagedBuffer::new_from_bytes(name.as_bytes());
        let uri_buf: ManagedBuffer<StaticApi> = ManagedBuffer::new_from_bytes(uri.as_bytes());
        let pk_buf: ManagedBuffer<StaticApi> = ManagedBuffer::new_from_bytes(&[0u8; 32]);

        // Contract uses #[allow_multiple_var_args] with TWO MultiValueEncodedCounted params:
        //   metadata: MultiValueEncodedCounted<MetadataEntry>
        //   services: MultiValueEncodedCounted<ServiceConfigInput>
        // Both require explicit u32 counts, even when empty.

        // Metadata count
        let metadata_count = metadata.len() as u32;
        let metadata_count_buf: ManagedBuffer<StaticApi> =
            ManagedBuffer::new_from_bytes(&metadata_count.to_be_bytes());

        let mut request = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(&self.contract_address)
            .gas(600_000_000)
            .raw_call("register_agent")
            .argument(&name_buf)
            .argument(&uri_buf)
            .argument(&pk_buf)
            .argument(&metadata_count_buf);

        if !metadata.is_empty() {
            for (key, value) in metadata {
                // Each MetadataEntry is nested-encoded: {key: ManagedBuffer, value: ManagedBuffer}
                let mut encoded_bytes = Vec::new();
                let key_len = (key.len() as u32).to_be_bytes();
                encoded_bytes.extend_from_slice(&key_len);
                encoded_bytes.extend_from_slice(key.as_bytes());

                let val_len = (value.len() as u32).to_be_bytes();
                encoded_bytes.extend_from_slice(&val_len);
                encoded_bytes.extend_from_slice(&value);

                let encoded_buf: ManagedBuffer<StaticApi> =
                    ManagedBuffer::new_from_bytes(&encoded_bytes);
                request = request.argument(&encoded_buf);
            }
        }

        // Services count (always 0 — not supported in this interactor)
        let services_count: u32 = 0;
        let services_count_buf: ManagedBuffer<StaticApi> =
            ManagedBuffer::new_from_bytes(&services_count.to_be_bytes());
        request = request.argument(&services_count_buf);

        request.run().await;

        println!("Registered Agent: {}", name);
    }

    pub fn address(&self) -> &Address {
        &self.contract_address
    }
}
