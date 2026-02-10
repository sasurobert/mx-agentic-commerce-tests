use multiversx_sc::types::{BigUint, ManagedBuffer};
use multiversx_sc_snippets::imports::*;
use mx_agentic_commerce_tests::ProcessManager;
use tokio::time::{sleep, Duration};

use crate::common::{vm_query, GATEWAY_URL};

#[tokio::test]
async fn test_reputation_averaging() {
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

    // 2. Complete 3 Jobs
    // Ratings: 80, 90, 60
    // Avg = floor((80 + 90 + 60) / 3) = 76

    let ratings = vec![80u64, 90u64, 60u64];
    let agent_nonce: u64 = 1;

    for (i, rating) in ratings.iter().enumerate() {
        let job_id = format!("job-avg-{}", i);
        let job_id_buf = ManagedBuffer::<StaticApi>::new_from_bytes(job_id.as_bytes());
        let agent_nonce_buf =
            ManagedBuffer::<StaticApi>::new_from_bytes(&agent_nonce.to_be_bytes());
        let rating_buf = ManagedBuffer::<StaticApi>::new_from_bytes(&rating.to_be_bytes());
        let employer_buf = ManagedBuffer::<StaticApi>::new_from_bytes(employer.as_bytes());
        let zero_proof = ManagedBuffer::<StaticApi>::new_from_bytes(b"proof");

        // Init
        interactor
            .tx()
            .from(&employer)
            .to(&validation_addr)
            .gas(10_000_000)
            .raw_call("init_job")
            .argument(&job_id_buf)
            .argument(&agent_nonce_buf)
            .run()
            .await;
        // Proof
        interactor
            .tx()
            .from(&owner)
            .to(&validation_addr)
            .gas(10_000_000)
            .raw_call("submit_proof")
            .argument(&job_id_buf)
            .argument(&zero_proof)
            .run()
            .await;
        // Verify
        interactor
            .tx()
            .from(&owner)
            .to(&validation_addr)
            .gas(10_000_000)
            .raw_call("verify_job")
            .argument(&job_id_buf)
            .run()
            .await;
        // Authorize
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
        // Submit
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
    }

    // 3. Verify Average Reputation Score
    let nonce_mb = ManagedBuffer::<StaticApi>::new_from_bytes(&agent_nonce.to_be_bytes());
    let result: Vec<Vec<u8>> = vm_query(
        &mut interactor,
        &reputation_addr,
        "reputation_score",
        vec![nonce_mb.clone()],
    )
    .await;

    let score_bytes = &result[0];
    let mut score_val: u64 = 0;
    for byte in score_bytes {
        score_val = (score_val << 8) | (*byte as u64);
    }
    println!("Final Reputation Score: {}", score_val);

    // Expected: (80 + 90 + 60) / 3 = 230 / 3 = 76.66 -> 76 (integer division)
    assert_eq!(score_val, 76, "Average score mismatch");

    // 4. Verify Total Jobs count
    let jobs_res: Vec<Vec<u8>> = vm_query(
        &mut interactor,
        &reputation_addr,
        "total_jobs",
        vec![nonce_mb],
    )
    .await;
    let jobs_bytes = &jobs_res[0];
    let mut jobs_val: u64 = 0;
    for byte in jobs_bytes {
        jobs_val = (jobs_val << 8) | (*byte as u64);
    }
    assert_eq!(jobs_val, 3, "Total jobs mismatch");
}
