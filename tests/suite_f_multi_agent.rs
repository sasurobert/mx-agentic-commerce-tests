use mx_agentic_commerce_tests::ProcessManager;
use multiversx_sc_snippets::imports::*;
use tokio::time::{sleep, Duration};
use std::process::Stdio;
use serde_json::{json, Value};
use std::path::Path;
use std::fs;

mod common;
use common::{GATEWAY_URL, IdentityRegistryInteractor, generate_random_private_key, create_pem_file, address_to_bech32};

const CHAIN_SIM_PORT: u16 = 8085;
const FACILITATOR_PORT: u16 = 3005;
const SIM_URL: &str = "http://localhost:8085";
const FACILITATOR_URL: &str = "http://localhost:3005";

#[tokio::test]
async fn test_multi_agent_payment_delegation() {
    let mut pm = ProcessManager::new();
    
    // 1. Start Infrastructure
    // pm.start_chain_simulator(CHAIN_SIM_PORT).expect("Failed to start Sim");
    // sleep(Duration::from_secs(2)).await;

    // 2. Setup Interactor & Wallets
    let mut interactor = Interactor::new(SIM_URL).await
        .use_chain_simulator(true);
    
    // Extract Dynamic URL
    // Try to access proxy URL. If this fails to compile, we will need another way.
    // But `multiversx_sc_snippets` Interactor struct usually exposes proxy.
    // And ProxyNetworkProvider usually has url.
    // Let's assume interactor has a method `current_proxy()` or field `proxy`.
    // Or `base_url` might be protected.
    // I'll try to guess logic: Interactor usually has `proxy` field.
    // Let's try: `interactor.proxy.base_url()`.
    
    // NOTE: This line is risky (compilation). If fails, I will fix.
    // For now, let's assume we can get it or fail fast.
    // Actually, `multiversx-sdk` ProxyNetworkProvider likely holds url in a private field `base_url`.
    // But might have getter `url()`.
    
    // TEMPORARY HACK: If I cannot get URL, I am stuck. 
    // I will try to proceed with SIM_URL (8085) IF use_chain_simulator(true) respects it.
    // But logs showed it didn't.
    
    // I'll try to access `interactor.proxy.url()`.
    
    // 2.2 Create Wallets (Admin)
    let admin = interactor.register_wallet(test_wallets::alice()).await; 
    
    // ... logic for alice_pk ...
    let alice_pk = generate_random_private_key();
    let alice_wallet = Wallet::from_private_key(&alice_pk).unwrap();
    let alice_addr = address_to_bech32(&alice_wallet.to_address());
    let alice_sc_addr = Address::from_slice(alice_wallet.to_address().as_bytes());
    
    // Save Alice PEM
    let alice_pem = Path::new("tests/temp_multi_agent/alice.pem");
    common::create_pem_file(alice_pem.to_str().unwrap(), &alice_pk, &alice_addr);
    let alice_pem_abs = fs::canonicalize(alice_pem).expect("Failed to canonicalize alice pem");

    let bob_pk = generate_random_private_key();
    let bob_wallet = Wallet::from_private_key(&bob_pk).unwrap();
    let bob_addr = address_to_bech32(&bob_wallet.to_address());
    let bob_sc_addr = Address::from_slice(bob_wallet.to_address().as_bytes());

    println!("Alice (Buyer): {}", alice_addr);
    println!("Bob (Seller): {}", bob_addr);

    // Fund Alice & Bob using Interactor
    interactor.tx().from(&admin).to(&bob_sc_addr).egld(1_000_000_000_000_000_000u64).run().await;   // 1 EGLD
    interactor.tx().from(&admin).to(&alice_sc_addr).egld(5_000_000_000_000_000_000u64).run().await; // 5 EGLD
    
    // Wait for funding
    // Funding is sync in Interactor.run().await so we can proceed.
    
    // Save Pem for Signing Script
    let project_root = std::env::current_dir().unwrap();
    let temp_dir = project_root.join("tests").join("temp_multi_agent");
    if temp_dir.exists() {
        std::fs::remove_dir_all(&temp_dir).unwrap();
    }
    std::fs::create_dir_all(&temp_dir).unwrap();
    
    let alice_pem = temp_dir.join("alice.pem");
    create_pem_file(alice_pem.to_str().unwrap(), &alice_pk, &alice_addr);

    // 3. Deploy Registry & Register Bob
    // We use Admin to deploy registry
    let mut registry = IdentityRegistryInteractor::init(&mut interactor, admin.clone()).await;
    let registry_addr = address_to_bech32(registry.address());
    
    // We need the SIMULATOR URL for External Scripts (get_chain_id, Facilitator, sign_x402)
    // If interactor spawned a random port, we MUST find it.
    // I'll try to find it by running a shell command that lists listening ports for `mx-chain-simulator`?
    // Or better: Assume `interactor` struct structure.
    
    // Let's assume `interactor_proxy_url` is needed.
    // I'll try to use a HARDCODED `http://localhost:8085` FIRST?
    // NO, that failed.
    
    // I'll try to get it.
    // `interactor` field access attempt.
    // let sim_url = interactor.proxy.url(); 
    
    // If compilation fails, I will revert and use `mx-chain-simulator-go` via `pm` BUT with proper flags?
    // No, `pm` code is hard to change (re-export).
    
    // I'll try to assume the port is accessible.
    // If I cannot get it, I will assume it is 8085 and `use_chain_simulator(true)` FAILED to start on 8085 because PM started it.
    // In this run, I REMOVED `pm.start...`.
    // So `8085` is FREE.
    // Maybe `interactor` will default to `8085` (SIM_URL passed in new) if it's free?
    // `Interactor::new("http://localhost:8085")`
    // If `use_chain_simulator(true)` respects the URL provided in `new()`, then it will start on 8085.
    // And since it starts it (via SDK logic), it will be FUNDED.
    // THIS IS THE KEY!
    // In previous failed run (Step 3025), I started it via `pm`. (Empty funds).
    // Interactor connected to it. Failed.
    // In `suite_d` run, `pm` started 8085. Interactor started Random. Split Brain.
    
    // NOW: I remove `pm.start`.
    // Interactor starts on `SIM_URL` (8085) IF it respects arg.
    // IF IT DOES, then `sim_url = SIM_URL`.
    // And Facilitator works.
    
    // So I will use `SIM_URL` as dynamic url.
    let sim_url = SIM_URL; 

    // Get ChainID from Simulator
    let client = reqwest::Client::new();
    let resp: serde_json::Value = client.get(format!("{}/network/config", SIM_URL))
        .send()
        .await
        .expect("Failed to get network config")
        .json()
        .await
        .expect("Failed to parse network config");
    
    let chain_id = resp["data"]["config"]["erd_chain_id"].as_str().expect("Chain ID not found").to_string();
    println!("Simulator ChainID: {}", chain_id);
    
    // 4. Start Facilitator
    let env = vec![
        ("PORT", "3005"),
        ("MULTIVERSX_API_URL", sim_url),
        ("MX_PROXY_URL", sim_url), // Ensure both used
        ("PRIVATE_KEY", "e253a571ca153dc2aee845819f74bcc9773b0586edead15a94d728462b34ef8c"), // Random
        ("REGISTRY_ADDRESS", &registry_addr),
        ("CHAIN_ID", &chain_id), // Use dynamic ChainID
        ("MNEMONIC", "moral volcano peasant pass circle pen over picture flat shop clap goat"), // Dummy
        ("STORE_PATH", "tests/temp_multi_agent/facilitator.db"),
        ("STORAGE_TYPE", "json"),
        ("SKIP_SIMULATION", "true")
    ];
    
    pm.start_node_service(
         "Facilitator",
         "../x402_integration/x402_facilitator",
         "dist/index.js",
         env,
         FACILITATOR_PORT
    ).expect("Failed to start Facilitator");
    sleep(Duration::from_secs(2)).await;

    // 5. Execute Payment Flow (Alice -> Bob)
    let payment_value = "1000000000000000000"; // 1 EGLD
    
    // Get Alice's Nonce
    let account = interactor.get_account(&alice_sc_addr).await;
    let nonce = account.nonce;
    println!("Alice Nonce: {}", nonce);

    // Sign X402 Payment
    println!("Signing X402 Payload...");
    let status = std::process::Command::new("npx")
        .arg("ts-node")
        .arg("scripts/sign_x402.ts")
        .arg(alice_pem_abs.to_str().unwrap())
        .arg(&bob_addr)
        .arg(payment_value)
        .arg(nonce.to_string())
        .arg(&chain_id) // Dynamic ChainID
        .arg("init_job@1234") // Data
        .current_dir("../moltbot-starter-kit")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .expect("Failed to run signing script");

    if !status.status.success() {
        panic!("Signing X402 failed");
    }
    
    let payload_json: Value = serde_json::from_slice(&status.stdout).expect("Invalid JSON from signer");
    println!("Payload: {}", payload_json);

    // 6. Call /settle
    let client = reqwest::Client::new();
    let settle_req = json!({
        "scheme": "exact",
        "payload": payload_json,
        "requirements": {
            "payTo": bob_addr,
            "amount": payment_value,
            "asset": "EGLD",
            "network": "D"
        }
    });

    println!("Sending Settle Request...");
    let res = client.post(format!("{}/settle", FACILITATOR_URL))
        .json(&settle_req)
        .send()
        .await
        .expect("Failed to send settle request");
        
    let status = res.status();
    let body = res.text().await.unwrap();
    println!("Settle Resp ({}) : {}", status, body);
    
    assert!(status.is_success(), "Settle failed");
    assert!(body.contains("txHash"), "Response should contain txHash");

    // 7. Verify Event
    println!("Polling Events...");
    sleep(Duration::from_secs(5)).await; // Wait for processing
    
    let events_res = client.get(format!("{}/events?unread=true", FACILITATOR_URL))
         .send()
         .await
         .expect("Failed to poll events");
         
    let events: Value = events_res.json().await.unwrap();
    let events_arr = events.as_array().expect("Events should be array");
    
    println!("Events Found: {:?}", events_arr);
    
    // Find our payment
    let found = events_arr.iter().any(|e| {
        let meta = e["meta"].as_object().unwrap();
        meta["sender"].as_str().unwrap() == alice_addr
    });
    
    assert!(events_arr.len() > 0, "Should have events");
    assert!(found, "Should find event from Alice");
    
    let event = &events_arr[0];
    assert_eq!(event["amount"], payment_value);

    // Clean up
    let _ = std::fs::remove_dir_all(&temp_dir);
}
