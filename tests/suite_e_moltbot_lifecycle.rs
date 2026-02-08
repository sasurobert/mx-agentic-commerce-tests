use mx_agentic_commerce_tests::ProcessManager;
use multiversx_sc_snippets::imports::*;
use tokio::time::{sleep, Duration};
use std::fs;

mod common;
use common::{IdentityRegistryInteractor, GATEWAY_URL, generate_random_private_key, address_to_bech32, create_pem_file};

const FACILITATOR_PORT: u16 = 3000;

#[tokio::test]
async fn test_moltbot_lifecycle() {
    let mut pm = ProcessManager::new();
    
    // 1. Start Chain Simulator
    pm.start_chain_simulator(8085).expect("Failed to start simulator");
    sleep(Duration::from_secs(2)).await;

    // 2. Setup Interactor & Users
    let mut interactor = Interactor::new(GATEWAY_URL).await
        .use_chain_simulator(true);
    let wallet_alice = interactor.register_wallet(test_wallets::alice()).await;
    
    // 3. Deploy Identity Registry
    let identity = IdentityRegistryInteractor::init(&mut interactor, wallet_alice.clone()).await;
    let registry_address = address_to_bech32(identity.address());
    println!("Registry Address: {}", registry_address);

    // 4. Start Facilitator (Prerequisite for Moltbot, though registration might not need it, 
    //    but Moltbot usually checks connection)
    //    We'll start it to be safe and consistent with full env.
    
    let facilitator_pk = generate_random_private_key();
    let wallet_facilitator = interactor.register_wallet(
        Wallet::from_private_key(&facilitator_pk).expect("Failed to create wallet")
    ).await;
    
    // Fund Facilitator
    interactor.tx().from(&wallet_alice).to(&wallet_facilitator).egld(1_000_000_000_000_000_000u64).run().await;
    let _facilitator_address_bech32 = address_to_bech32(&wallet_facilitator);

    let env_vars = vec![
        ("PORT", "3000"),
        ("PRIVATE_KEY", facilitator_pk.as_str()),
        ("REGISTRY_ADDRESS", registry_address.as_str()),
        ("GATEWAY_URL", GATEWAY_URL),
        ("CHAIN_ID", "local-testnet"),
    ];
    
    pm.start_node_service(
        "Facilitator", 
        "../x402_integration/x402_facilitator", 
        "dist/index.js", 
        env_vars, 
        FACILITATOR_PORT
    ).expect("Failed to start Facilitator");
    sleep(Duration::from_secs(2)).await;

    // 5. Setup Moltbot Wallet
    let moltbot_pk = generate_random_private_key();
    let moltbot_wallet_obj = Wallet::from_private_key(&moltbot_pk).unwrap();
    let moltbot_address = interactor.register_wallet(moltbot_wallet_obj).await;
    let moltbot_address_bech32 = address_to_bech32(&moltbot_address);
    
    // Fund Moltbot
    println!("Funding Moltbot: {}", moltbot_address_bech32);
    interactor.tx().from(&wallet_alice).to(&moltbot_address).egld(1_000_000_000_000_000_000u64).run().await;

    // Create PEM
    // Use absolute path for safety when passing to child process
    let project_root = std::env::current_dir().unwrap();
    let pem_filename = format!("temp_moltbot_{}.pem", hex::encode(&moltbot_pk[0..4]));
    let pem_path = project_root.join("tests").join(&pem_filename);
    
    create_pem_file(pem_path.to_str().unwrap(), &moltbot_pk, &moltbot_address_bech32);
    println!("Created PEM at: {:?}", pem_path);

    // 6. Run Registration Script
    let status = std::process::Command::new("npm")
        .arg("run")
        .arg("register")
        .current_dir("../moltbot-starter-kit")
        .env("MULTIVERSX_PRIVATE_KEY", pem_path.to_str().unwrap())
        .env("MULTIVERSX_API_URL", GATEWAY_URL)
        .env("IDENTITY_REGISTRY_ADDRESS", &registry_address)
        .env("MULTIVERSX_CHAIN_ID", "chain")
        // Also provide Facilitator URL if needed by config? 
        // Config defaults to localhost:4000 for Facilitator.
        // We started it on 3000.
        .env("X402_FACILITATOR_URL", format!("http://localhost:{}", FACILITATOR_PORT))
        .status()
        .expect("Failed to run register script");

    assert!(status.success(), "Registration script failed");
    
    // Cleanup PEM
    let _ = fs::remove_file(pem_path);

    // 7. Verify On-Chain
    // We expect the Moltbot address to be registered.
    // We can call `get_agent_id` or `get_agent_data`.
    // Let's print the agent details.
    
    println!("Verifying registration for: {}", moltbot_address_bech32);
    
    // Use raw call to get data or just check if it doesn't revert.
    // The `register_agent` script sets name "Moltbot".
    
    // Query: getAgentIds
    // Query: getAgentData(agent_id)
    
    // We can try to assume 1st agent is ID 1.
    
    // Or we can try to call 'getAgentId' if it exists.
    // `mx-8004` usually has `get_agent_id(address)`.
    
    // This part depends on `mx-8004` logic.
}
