use crate::common::{
    create_pem_file, fund_address_on_simulator_custom, generate_random_private_key,
    EscrowInteractor, EscrowStatus, IdentityRegistryInteractor, ValidationRegistryInteractor,
};
use multiversx_sc_snippets::imports::*;
use mx_agentic_commerce_tests::ProcessManager;
use tokio::time::{sleep, Duration};

const GATEWAY_URL: &str = "http://localhost:8094";

/// S-006: Multi-job — deposit 3 jobs → release 1 → verify states independently
#[tokio::test]
async fn test_escrow_multi_job() {
    let mut process_manager = ProcessManager::new();
    process_manager
        .start_chain_simulator(8094)
        .expect("Failed to start simulator");
    sleep(Duration::from_secs(3)).await;

    let mut interactor = Interactor::new(GATEWAY_URL).await.use_chain_simulator(true);

    // 1. Setup
    let owner_key = generate_random_private_key();
    let owner_wallet = Wallet::from_private_key(&owner_key).unwrap();
    let owner_address = owner_wallet.to_address();

    let worker_key = generate_random_private_key();
    let worker_wallet = Wallet::from_private_key(&worker_key).unwrap();
    let worker_address = worker_wallet.to_address();

    let pem_path = "test_escrow_multi.pem";
    create_pem_file(
        pem_path,
        &owner_key,
        &owner_address.to_bech32("erd").to_string(),
    );
    interactor.register_wallet(owner_wallet.clone()).await;
    interactor.register_wallet(worker_wallet.clone()).await;

    fund_address_on_simulator_custom(
        &owner_address.to_bech32("erd").to_string(),
        "100000000000000000000000",
        GATEWAY_URL,
    )
    .await;

    // 2. Deploy
    let mut identity =
        IdentityRegistryInteractor::init(&mut interactor, owner_address.clone()).await;
    identity
        .issue_token(&mut interactor, "AgentToken", "AGENT")
        .await;
    identity
        .register_agent(&mut interactor, "MultJobWorker", "uri://multijob", vec![])
        .await;

    let mut validation = ValidationRegistryInteractor::init(
        &mut interactor,
        owner_address.clone(),
        identity.address(),
    )
    .await;

    let escrow = EscrowInteractor::deploy(
        &mut interactor,
        owner_address.clone(),
        validation.address(),
        identity.address(),
    )
    .await;

    // 3. Deposit 3 separate jobs
    let jobs = ["job-multi-001", "job-multi-002", "job-multi-003"];
    let amounts = [
        1_000_000_000_000_000_000u64,
        2_000_000_000_000_000_000u64,
        3_000_000_000_000_000_000u64,
    ];

    for (job_id, amount) in jobs.iter().zip(amounts.iter()) {
        escrow
            .deposit_egld(
                &mut interactor,
                job_id,
                &worker_address,
                &format!("poa-{}", job_id),
                9_999_999_999u64,
                *amount,
            )
            .await;
    }

    // 4. Verify all 3 are Active
    for job_id in &jobs {
        let data = escrow.get_escrow(&mut interactor, job_id).await;
        assert_eq!(data.status, EscrowStatus::Active);
    }

    // 5. Complete and release only the first job
    validation.init_job(&mut interactor, jobs[0], 1).await;
    validation
        .submit_proof(&mut interactor, jobs[0], "proof-multi-001")
        .await;
    validation
        .validation_request(
            &mut interactor,
            jobs[0],
            &owner_address,
            "https://v.uri",
            "req_multi_001",
        )
        .await;
    validation
        .validation_response(
            &mut interactor,
            "req_multi_001",
            85,
            "https://resp.uri",
            "resp_multi_001",
            "quality",
        )
        .await;

    escrow.release(&mut interactor, jobs[0]).await;

    // 6. Verify: job 0 = Released, jobs 1 & 2 = still Active
    let data_0 = escrow.get_escrow(&mut interactor, jobs[0]).await;
    assert_eq!(data_0.status, EscrowStatus::Released);

    let data_1 = escrow.get_escrow(&mut interactor, jobs[1]).await;
    assert_eq!(data_1.status, EscrowStatus::Active);

    let data_2 = escrow.get_escrow(&mut interactor, jobs[2]).await;
    assert_eq!(data_2.status, EscrowStatus::Active);

    // 7. Can't deposit to an existing job
    escrow
        .deposit_egld_expect_err(
            &mut interactor,
            jobs[1],
            &worker_address,
            "poa-dup",
            9_999_999_999u64,
            1_000_000_000_000_000_000,
            "Escrow already exists for this job",
        )
        .await;

    println!("✅ S-006 PASSED: Multi-job escrow state isolation verified");

    std::fs::remove_file(pem_path).unwrap_or(());
}
