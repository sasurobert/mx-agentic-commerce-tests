use multiversx_sc::types::ManagedBuffer;
use multiversx_sc_snippets::imports::*;
use mx_agentic_commerce_tests::ProcessManager;
use tokio::time::{sleep, Duration};

use crate::common::GATEWAY_URL;

#[tokio::test]
async fn test_authorize_feedback() {
    let mut pm = ProcessManager::new();
    pm.start_chain_simulator(8085)
        .expect("Failed to start simulator");
    sleep(Duration::from_secs(2)).await;

    let mut interactor = Interactor::new(GATEWAY_URL).await.use_chain_simulator(true);
    let owner = interactor.register_wallet(test_wallets::alice()).await;
    let employer = interactor.register_wallet(test_wallets::bob()).await;

    // 1. Deploy All Registries
    let (mut identity, validation_addr, reputation_addr) =
        crate::common::deploy_all_registries(&mut interactor, owner.clone()).await;

    // Register Agent
    identity
        .register_agent(
            &mut interactor,
            "WorkerBot",
            "https://workerbot.example.com/manifest.json",
            vec![],
        )
        .await;
    drop(identity);

    // 2. Init Job & Verify (Prerequisite)
    let job_id = "job-auth-test";
    let job_id_buf = ManagedBuffer::<StaticApi>::new_from_bytes(job_id.as_bytes());
    let agent_nonce: u64 = 1;
    let agent_nonce_buf = ManagedBuffer::<StaticApi>::new_from_bytes(&agent_nonce.to_be_bytes());

    interactor
        .tx()
        .from(&employer) // Employer inits job
        .to(&validation_addr)
        .gas(20_000_000)
        .raw_call("init_job")
        .argument(&job_id_buf)
        .argument(&agent_nonce_buf)
        .run()
        .await;

    // Verify job (owner simulates verification)
    interactor
        .tx()
        .from(&owner)
        .to(&validation_addr)
        .gas(10_000_000)
        .raw_call("verify_job")
        .argument(&job_id_buf)
        .run()
        .await;

    // 3. Authorize Feedback (Happy Path)
    // Must be called by AGENT OWNER (Alice)
    let employer_buf = ManagedBuffer::<StaticApi>::new_from_bytes(employer.as_bytes());

    interactor
        .tx()
        .from(&owner)
        .to(&reputation_addr)
        .gas(10_000_000)
        .raw_call("authorize_feedback")
        .argument(&job_id_buf)
        .argument(&employer_buf)
        .run()
        .await;

    println!("Authorize Feedback Success");
}
