use crate::common::{
    create_pem_file, fund_address_on_simulator_custom, generate_random_private_key,
    IdentityRegistryInteractor, ValidationRegistryInteractor, GATEWAY_URL,
};
use multiversx_sc_snippets::imports::*;
use mx_agentic_commerce_tests::ProcessManager;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_clean_old_jobs() {
    let mut pm = ProcessManager::new();
    pm.start_chain_simulator(8085) // Port 8085
        .expect("Failed to start simulator");
    sleep(Duration::from_secs(3)).await;

    let mut interactor = Interactor::new(GATEWAY_URL).await.use_chain_simulator(true);

    // Setup Owner
    let owner_private_key = generate_random_private_key();
    let owner_wallet = Wallet::from_private_key(&owner_private_key).unwrap();
    let owner_address = owner_wallet.to_address();
    create_pem_file(
        "owner_clean.pem",
        &owner_private_key,
        &owner_address.to_bech32("erd").to_string(),
    );
    interactor.register_wallet(owner_wallet.clone()).await;
    fund_address_on_simulator_custom(
        &owner_address.to_bech32("erd").to_string(),
        "100000000000000000000000",
        GATEWAY_URL,
    )
    .await;

    // Deploy Registries
    let mut identity_interactor =
        IdentityRegistryInteractor::init(&mut interactor, owner_address.clone()).await;
    identity_interactor
        .issue_token(&mut interactor, "AgentToken", "AGENT")
        .await;

    let mut validation_interactor = ValidationRegistryInteractor::init(
        &mut interactor,
        owner_address.clone(),
        identity_interactor.address(),
    )
    .await;

    // 1. Init "old" job
    let old_job_id = "job-old";
    validation_interactor
        .init_job(&mut interactor, old_job_id, 1)
        .await;

    // 2. Advance time by > 3 days (3 * 24 * 3600 = 259200 seconds)
    // Block time approx 6s -> 43200 blocks.
    // Simulator might be faster/slower, but generating blocks advances timestamp.
    println!("Generating 44,000 blocks to simulate 3 days passing...");
    // We split into chunks to avoid timeout?
    // 44,000 blocks might take a while.
    // Let's try 4400 first to see how fast it is.
    // Actually, simulator `generate-blocks` endpoint usually generates them instantly without sleeping 6s.

    // We'll use 44000 to be safe.
    interactor.generate_blocks(44000).await;

    // 3. Init "new" job
    let new_job_id = "job-new";
    validation_interactor
        .init_job(&mut interactor, new_job_id, 1) // Nonce doesn't matter much for this test
        .await;

    // 4. Call clean_old_jobs
    validation_interactor
        .clean_old_jobs(&mut interactor, vec![old_job_id, new_job_id])
        .await;

    // 5. Verify old job is GONE (or error on get?)
    // ValidationRegistry doesn't expose `get_job_data` view in our interactor?
    // Wait, common/mod.rs doesn't have `get_job_data` view method.
    // I need to add it to check status.
    // BUT `init_job` fails if job ID exists.
    // So if old job is gone, I should be able to init it again?
    // Or `clean_old_jobs` might verify it inside?

    // Let's verify by trying to init old_job again.
    // If it succeeds, it was cleaned.
    // If it fails with "Already initialized", it wasn't cleaned.

    println!("Verifying old job removal...");
    validation_interactor
        .init_job(&mut interactor, old_job_id, 1)
        .await; // Should succeed now

    // 6. Verify new job is NOT gone
    // Try to init new_job again -> Should fail
    println!("Verifying new job persistence...");
    let err = interactor
        .tx()
        .from(&owner_address)
        .to(validation_interactor.address())
        .gas(600_000_000)
        .raw_call("init_job")
        .argument(&ManagedBuffer::<StaticApi>::new_from_bytes(
            new_job_id.as_bytes(),
        ))
        .argument(&1u64)
        .returns(ExpectError(4, "")) // Should fail
        .run()
        .await;

    // Cleanup
    std::fs::remove_file("owner_clean.pem").unwrap_or(());
}
