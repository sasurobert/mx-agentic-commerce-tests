use mx_agentic_commerce_tests::ProcessManager;
use multiversx_sc_snippets::imports::*;
use tokio::time::{sleep, Duration};
use reqwest;
use rand::RngCore;
use bech32::{self, Hrp, Bech32};

mod common;
use common::{IdentityRegistryInteractor, GATEWAY_URL};

const FACILITATOR_PORT: u16 = 3000;

fn generate_random_private_key() -> String {
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);
    hex::encode(key)
}

fn address_to_bech32(address: &Address) -> String {
    let hrp = Hrp::parse("erd").expect("Invalid HRP");
    bech32::encode::<Bech32>(hrp, address.as_bytes()).expect("Failed to encode address")
}

#[tokio::test]
async fn test_facilitator_flow() {
    let mut pm = ProcessManager::new();
    
    // 1. Start Chain Simulator
    pm.start_chain_simulator(8085).expect("Failed to start simulator");
    sleep(Duration::from_secs(2)).await;

    // 2. Setup Interactor & Users
    let mut interactor = Interactor::new(GATEWAY_URL).await
        .use_chain_simulator(true);
    let wallet_alice = interactor.register_wallet(test_wallets::alice()).await;
    
    // Generate Facilitator Wallet
    let facilitator_pk = generate_random_private_key();
    let wallet_facilitator_address = interactor.register_wallet(
        Wallet::from_private_key(&facilitator_pk).expect("Failed to create wallet")
    ).await;

    // Fund Facilitator
    interactor.tx()
        .from(&wallet_alice)
        .to(&wallet_facilitator_address)
        .egld(1_000_000_000_000_000_000u64) // 1 EGLD
        .run()
        .await;

    println!("Facilitator Address: {}", address_to_bech32(&wallet_facilitator_address));

    // 3. Deploy Identity Registry
    let identity = IdentityRegistryInteractor::init(&mut interactor, wallet_alice.clone()).await;
    
    let registry_address = address_to_bech32(identity.address());
    println!("Registry Address: {}", registry_address);

    // 4. Start Facilitator
    let chain_id = common::get_simulator_chain_id().await;
    println!("Simulator ChainID: {}", chain_id);

    let env_vars = vec![
        ("PORT", "3000"),
        ("PRIVATE_KEY", facilitator_pk.as_str()),
        ("REGISTRY_ADDRESS", registry_address.as_str()),
        ("NETWORK_PROVIDER", GATEWAY_URL), // CRITICAL FIX
        ("GATEWAY_URL", GATEWAY_URL),
        ("CHAIN_ID", chain_id.as_str()), // Simulator chain ID
    ];
    
    // Path relative to mx-agentic-commerce-tests root
    pm.start_node_service(
        "Facilitator", 
        "../x402_integration/x402_facilitator", 
        "dist/index.js", 
        env_vars, 
        FACILITATOR_PORT
    ).expect("Failed to start Facilitator");

    sleep(Duration::from_secs(5)).await;

    // 5. Test Health
    let client = reqwest::Client::new();
    let resp = client.get(format!("http://localhost:{}/health", FACILITATOR_PORT))
        .send()
        .await
        .expect("Failed to call health endpoint");
        
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        panic!("Health check failed with status: {}, body: {}", status, body);
    }
    
    println!("Facilitator health check passed");
}
