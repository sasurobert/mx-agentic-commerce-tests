use mx_agentic_commerce_tests::ProcessManager;
use multiversx_sc_snippets::imports::*;
use tokio::time::{sleep, Duration};

mod common;
use common::{IdentityRegistryInteractor, GATEWAY_URL};

#[tokio::test]
async fn test_identity_registry_flow() {
    let mut pm = ProcessManager::new();
    pm.start_chain_simulator(8085).expect("Failed to start simulator");

    sleep(Duration::from_secs(2)).await;

    let mut interactor = Interactor::new(GATEWAY_URL).await
        .use_chain_simulator(true);

    let wallet_alice = interactor.register_wallet(test_wallets::alice()).await;
    
    println!("Identity Registry Flow Test Started");

    let mut identity = IdentityRegistryInteractor::init(&mut interactor, wallet_alice.clone()).await;

    identity.issue_token("AgentToken", "AGENT").await;
    
    // Test metadata registration (Fix Verification)
    let price: u64 = 1_000_000_000_000_000_000;
    let metadata = vec![
        ("price:default", price.to_be_bytes().to_vec()),
        ("token:default", "EGLD".as_bytes().to_vec())
    ];
    
    identity.register_agent("MyAgent", "https://example.com/agent.json", metadata).await;
    
    drop(identity); 
    
    sleep(Duration::from_secs(1)).await;
}
