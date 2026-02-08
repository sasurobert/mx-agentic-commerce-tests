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
    pm.start_chain_simulator(CHAIN_SIM_PORT).expect("Failed to start Sim");
    sleep(Duration::from_secs(2)).await;

    // 2. Setup Interactor & Wallets
    let mut interactor = Interactor::new(SIM_URL).await
        .use_chain_simulator(true);

    // 2. Create Wallets
    let admin = interactor.register_wallet(test_wallets::alice()).await; // Admin (Genesis Alice)
    
    // Create Admin PEM for mxpy
    let admin_pem_path = Path::new("tests/temp_multi_agent/admin.pem");
    // Alice Genesis Private Key (standard devnet)
    let admin_priv_key = "413f42575f7f26fad3317a778771212fdb80245850181cb4c9ce61db51c4b8e7";
    common::create_pem_file(admin_pem_path.to_str().unwrap(), admin_priv_key, "erd1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssycr6th");
    let admin_pem_abs = fs::canonicalize(admin_pem_path).expect("Failed to canonicalize admin pem");

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

    // Fund Alice & Bob using mxpy on Chain D
    // Bob can be funded via interactor on "chain" (he doesn't sign txs in this flow, he just receives)
    interactor.tx().from(&admin).to(&bob_sc_addr).egld(1_000_000_000_000_000_000u64).run().await;   // 1 EGLD
    
    // Fund Alice on Chain D via fund.ts
    println!("Funding Alice on Chain D...");
    let status = std::process::Command::new("npx")
        .arg("ts-node")
        .arg("scripts/fund.ts")
        .arg(admin_pem_abs.to_str().unwrap())
        .arg(&alice_addr)
        .arg("5000000000000000000") // 5 EGLD
        .arg("D") // ChainID
        .arg(SIM_URL)
        .current_dir("../moltbot-starter-kit")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .expect("Failed to run fund.ts");
        
    if !status.status.success() {
         panic!("Funding Alice via fund.ts failed");
    }
    
    // Wait for funding
    let mut funding_attempts = 0;
    loop {
        let acc = interactor.get_account(&alice_sc_addr).await;
        if acc.balance.parse::<u64>().unwrap_or(0) > 0 {
            println!("Alice Funded: {}", acc.balance);
            break;
        }
        sleep(Duration::from_millis(500)).await;
    }
    sleep(Duration::from_secs(5)).await; // Ensure sync for simulation

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
    
    // 4. Start Facilitator
    let env = vec![
        ("PORT", "3005"),
        ("MULTIVERSX_API_URL", SIM_URL),
        ("MNEMONIC", "moral volcano peasant pass circle pen over picture flat shop clap goat"), // Dummy
        ("STORE_PATH", "tests/temp_multi_agent/facilitator.db"),
        ("STORAGE_TYPE", "json"),
        ("CHAIN_ID", "D"),
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

    // Sign X402 Payment
    println!("Signing X402 Payload...");
    let status = std::process::Command::new("npx")
        .arg("ts-node")
        .arg("scripts/sign_x402.ts")
        .arg(alice_pem_abs.to_str().unwrap())
        .arg(&bob_addr)
        .arg(payment_value)
        .arg(nonce.to_string())
        .arg("D") // ChainID enforced to D
        // .arg(&chain_id) // ChainID
        // .arg("local-testnet") // ChainID, Force local-testnet
        .arg("init_job@1234") // Data
        .current_dir("../moltbot-starter-kit")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .expect("Failed to run signing script");

    if !status.status.success() {
        panic!("Signing failed");
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
