use multiversx_sc::types::{BigUint, ManagedBuffer};
use multiversx_sc_snippets::imports::*;
use mx_agentic_commerce_tests::ProcessManager;
use tokio::time::{sleep, Duration};

use crate::common::{vm_query, GATEWAY_URL};

#[tokio::test]
async fn test_submit_feedback() {
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

    // Register Agent (Nonce 1)
    identity
        .register_agent(
            &mut interactor,
            "WorkerBot",
            "https://workerbot.example.com/manifest.json",
            vec![],
        )
        .await;
    drop(identity);

    // 2. Init Job, Submit Proof, Verify Job
    let job_id = "job-feedback-1";
    let job_id_buf = ManagedBuffer::<StaticApi>::new_from_bytes(job_id.as_bytes());
    let agent_nonce: u64 = 1;
    let agent_nonce_buf = ManagedBuffer::<StaticApi>::new_from_bytes(&agent_nonce.to_be_bytes());

    // Init (Employer)
    interactor
        .tx()
        .from(&employer)
        .to(&validation_addr)
        .gas(20_000_000)
        .raw_call("init_job")
        .argument(&job_id_buf)
        .argument(&agent_nonce_buf)
        .run()
        .await;

    // Proof (Agent/Owner)
    let proof = "proof-hash-1";
    let proof_buf = ManagedBuffer::<StaticApi>::new_from_bytes(proof.as_bytes());
    interactor
        .tx()
        .from(&owner)
        .to(&validation_addr)
        .gas(20_000_000)
        .raw_call("submit_proof")
        .argument(&job_id_buf)
        .argument(&proof_buf)
        .run()
        .await;

    // Verify (Owner)
    interactor
        .tx()
        .from(&owner)
        .to(&validation_addr)
        .gas(10_000_000)
        .raw_call("verify_job")
        .argument(&job_id_buf)
        .run()
        .await;

    // 3. Authorize Feedback (Agent Owner)
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

    // 4. Submit Feedback (Employer) -> Rating 80
    let rating: u64 = 80;
    let rating_buf = ManagedBuffer::<StaticApi>::new_from_bytes(&rating.to_be_bytes());

    interactor
        .tx()
        .from(&employer)
        .to(&reputation_addr)
        .gas(10_000_000)
        .raw_call("submit_feedback")
        .argument(&job_id_buf)
        .argument(&agent_nonce_buf)
        .argument(&rating_buf)
        .run()
        .await;

    println!("Feedback Submitted: {}", rating);

    // 5. Verify Reputation Score via VM Query
    // reputation_score(agent_nonce) -> BigUint
    let nonce_mb = ManagedBuffer::<StaticApi>::new_from_bytes(&agent_nonce.to_be_bytes());
    let result: Vec<Vec<u8>> = vm_query(
        &mut interactor,
        &reputation_addr,
        "reputation_score",
        vec![nonce_mb.clone()],
    )
    .await;
    assert!(!result.is_empty());

    // Parse BigUint
    let score_bytes = &result[0];
    let mut score_val: u64 = 0;
    for byte in score_bytes {
        score_val = (score_val << 8) | (*byte as u64);
    }
    println!("Reputation Score: {}", score_val);
    assert_eq!(score_val, 80, "Score should be 80 after single feedback");

    // 6. Verify Total Jobs
    // total_jobs(agent_nonce) -> u64/BigUint? Likely BigUint or u64
    // Let's assume BigUint based on standard getters
    let jobs_res: Vec<Vec<u8>> = vm_query(
        &mut interactor,
        &reputation_addr,
        "total_jobs",
        vec![nonce_mb],
    )
    .await;
    assert!(!jobs_res.is_empty());
    let jobs_bytes = &jobs_res[0];
    let mut jobs_val: u64 = 0;
    for byte in jobs_bytes {
        jobs_val = (jobs_val << 8) | (*byte as u64);
    }
    println!("Total Jobs: {}", jobs_val);
    assert_eq!(jobs_val, 1, "Should have 1 job");
}
