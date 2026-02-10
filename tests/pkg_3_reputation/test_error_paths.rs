use multiversx_sc::types::ManagedBuffer;
use multiversx_sc_snippets::imports::*;
use mx_agentic_commerce_tests::ProcessManager;
use tokio::time::{sleep, Duration};

use crate::common::{address_to_bech32, deploy_all_registries, fund_address_on_simulator};

const GATEWAY_PORT: u16 = 8085;
const GATEWAY_URL: &str = "http://localhost:8085";

/// Returns (pm, interactor, reputation_addr, validation_addr, owner, employer, mallory)
/// NOTE: pm MUST be kept alive for the duration of the test to prevent the simulator from being killed.
async fn setup_env() -> (
    ProcessManager,
    Interactor,
    Address,
    Address,
    Address,
    Address,
    Address,
) {
    let mut pm = ProcessManager::new();
    pm.start_chain_simulator(GATEWAY_PORT)
        .expect("Failed to start simulator");
    sleep(Duration::from_secs(2)).await;

    let mut interactor = Interactor::new(GATEWAY_URL).await.use_chain_simulator(true);

    // Register ALL wallets immediately while simulator is fresh
    let owner = interactor.register_wallet(test_wallets::alice()).await;
    let employer = interactor.register_wallet(test_wallets::bob()).await;
    let mallory = interactor.register_wallet(test_wallets::carol()).await;

    fund_address_on_simulator(&address_to_bech32(&owner), "100000000000000000000").await;
    fund_address_on_simulator(&address_to_bech32(&employer), "100000000000000000000").await;
    fund_address_on_simulator(&address_to_bech32(&mallory), "100000000000000000000").await;

    let (identity, validation_addr, reputation_addr) =
        deploy_all_registries(&mut interactor, owner.clone()).await;

    // Setup: Register Agent -> Init Job -> Verify Job
    identity
        .register_agent(&mut interactor, "Bot", "uri", vec![])
        .await;

    let job_id = "job-rep-err";
    let job_id_buf = ManagedBuffer::<StaticApi>::new_from_bytes(job_id.as_bytes());
    let agent_nonce = 1u64;

    // Init Job
    interactor
        .tx()
        .from(&employer)
        .to(&validation_addr)
        .gas(20_000_000)
        .raw_call("init_job")
        .argument(&job_id_buf)
        .argument(&agent_nonce)
        .run()
        .await;

    // Submit Proof
    interactor
        .tx()
        .from(&owner)
        .to(&validation_addr)
        .gas(20_000_000)
        .raw_call("submit_proof")
        .argument(&job_id_buf)
        .argument(&ManagedBuffer::<StaticApi>::new_from_bytes(b"proof"))
        .run()
        .await;

    // Verify Job
    interactor
        .tx()
        .from(&owner)
        .to(&validation_addr)
        .gas(20_000_000)
        .raw_call("verify_job")
        .argument(&job_id_buf)
        .run()
        .await;

    (
        pm,
        interactor,
        reputation_addr,
        validation_addr,
        owner,
        employer,
        mallory,
    )
}

#[tokio::test]
async fn test_authorize_feedback_non_owner() {
    let (_pm, mut interactor, reputation_addr, _, _, employer, mallory) = setup_env().await;

    let job_id_buf = ManagedBuffer::<StaticApi>::new_from_bytes(b"job-rep-err");

    interactor
        .tx()
        .from(&mallory)
        .to(&reputation_addr)
        .gas(20_000_000)
        .raw_call("authorize_feedback")
        .argument(&job_id_buf)
        .argument(&employer)
        .returns(ExpectError(
            4,
            "Only the agent owner can perform this action",
        ))
        .run()
        .await;
}

#[tokio::test]
async fn test_submit_feedback_unauthorized() {
    let (_pm, mut interactor, reputation_addr, _, _, employer, _) = setup_env().await;

    // Authorization skipped

    let job_id_buf = ManagedBuffer::<StaticApi>::new_from_bytes(b"job-rep-err");
    let rating = 90u64;

    interactor
        .tx()
        .from(&employer)
        .to(&reputation_addr)
        .gas(20_000_000)
        .raw_call("submit_feedback")
        .argument(&job_id_buf)
        .argument(&1u64) // agent nonce
        .argument(&rating)
        .returns(ExpectError(4, "Feedback not authorized by agent"))
        .run()
        .await;
}

#[tokio::test]
async fn test_authorize_feedback_nonexistent_job() {
    let (_pm, mut interactor, reputation_addr, _, _, employer, _) = setup_env().await;

    let fake_job_id = ManagedBuffer::<StaticApi>::new_from_bytes(b"nonexistent-job");

    interactor
        .tx()
        .from(&employer)
        .to(&reputation_addr)
        .gas(20_000_000)
        .raw_call("authorize_feedback")
        .argument(&fake_job_id)
        .argument(&employer)
        .returns(ExpectError(4, "Job not found"))
        .run()
        .await;
}

#[tokio::test]
async fn test_submit_feedback_non_employer() {
    let (_pm, mut interactor, reputation_addr, _, _, employer, mallory) = setup_env().await;

    let job_id_buf = ManagedBuffer::<StaticApi>::new_from_bytes(b"job-rep-err");

    // Owner authorizes feedback for the actual employer
    let owner = interactor.register_wallet(test_wallets::alice()).await;
    interactor
        .tx()
        .from(&owner)
        .to(&reputation_addr)
        .gas(20_000_000)
        .raw_call("authorize_feedback")
        .argument(&job_id_buf)
        .argument(&employer)
        .run()
        .await;

    // Mallory (not the employer) tries to submit feedback
    interactor
        .tx()
        .from(&mallory)
        .to(&reputation_addr)
        .gas(20_000_000)
        .raw_call("submit_feedback")
        .argument(&job_id_buf)
        .argument(&1u64) // agent nonce
        .argument(&80u64) // rating
        .returns(ExpectError(4, "Only the employer can provide feedback"))
        .run()
        .await;
}

#[tokio::test]
async fn test_submit_feedback_unverified_job() {
    // Setup env but with an UNVERIFIED job (only init_job, no submit_proof + verify_job)
    let mut pm = ProcessManager::new();
    pm.start_chain_simulator(GATEWAY_PORT)
        .expect("Failed to start simulator");
    sleep(Duration::from_secs(2)).await;

    let mut interactor = Interactor::new(GATEWAY_URL).await.use_chain_simulator(true);
    let owner = interactor.register_wallet(test_wallets::alice()).await;
    let employer = interactor.register_wallet(test_wallets::bob()).await;

    fund_address_on_simulator(&address_to_bech32(&owner), "100000000000000000000").await;
    fund_address_on_simulator(&address_to_bech32(&employer), "100000000000000000000").await;

    let (identity, validation_addr, reputation_addr) =
        deploy_all_registries(&mut interactor, owner.clone()).await;

    identity
        .register_agent(&mut interactor, "Bot", "uri", vec![])
        .await;

    let job_id_buf = ManagedBuffer::<StaticApi>::new_from_bytes(b"unverified-job");

    // Init Job only — do NOT submit_proof or verify_job
    interactor
        .tx()
        .from(&employer)
        .to(&validation_addr)
        .gas(20_000_000)
        .raw_call("init_job")
        .argument(&job_id_buf)
        .argument(&1u64)
        .run()
        .await;

    // Authorize feedback (owner does this)
    interactor
        .tx()
        .from(&owner)
        .to(&reputation_addr)
        .gas(20_000_000)
        .raw_call("authorize_feedback")
        .argument(&job_id_buf)
        .argument(&employer)
        .run()
        .await;

    // Employer tries to submit feedback on unverified job
    interactor
        .tx()
        .from(&employer)
        .to(&reputation_addr)
        .gas(20_000_000)
        .raw_call("submit_feedback")
        .argument(&job_id_buf)
        .argument(&1u64)
        .argument(&80u64)
        .returns(ExpectError(4, "Job not verified"))
        .run()
        .await;
}

#[tokio::test]
async fn test_submit_feedback_duplicate() {
    let (_pm, mut interactor, reputation_addr, _, owner, employer, _) = setup_env().await;

    let job_id_buf = ManagedBuffer::<StaticApi>::new_from_bytes(b"job-rep-err");

    // Owner authorizes feedback
    interactor
        .tx()
        .from(&owner)
        .to(&reputation_addr)
        .gas(20_000_000)
        .raw_call("authorize_feedback")
        .argument(&job_id_buf)
        .argument(&employer)
        .run()
        .await;

    // First feedback — should succeed
    interactor
        .tx()
        .from(&employer)
        .to(&reputation_addr)
        .gas(20_000_000)
        .raw_call("submit_feedback")
        .argument(&job_id_buf)
        .argument(&1u64)
        .argument(&80u64)
        .run()
        .await;

    // Second feedback — should fail
    interactor
        .tx()
        .from(&employer)
        .to(&reputation_addr)
        .gas(20_000_000)
        .raw_call("submit_feedback")
        .argument(&job_id_buf)
        .argument(&1u64)
        .argument(&90u64)
        .returns(ExpectError(4, "Feedback already provided for this job"))
        .run()
        .await;
}

#[tokio::test]
async fn test_append_response_non_owner() {
    let (_pm, mut interactor, reputation_addr, _, _, _owner, mallory) = setup_env().await;

    let job_id_buf = ManagedBuffer::<StaticApi>::new_from_bytes(b"job-rep-err");
    let response_uri = ManagedBuffer::<StaticApi>::new_from_bytes(b"https://response.example.com");

    // Mallory (not the agent owner) tries to append response
    interactor
        .tx()
        .from(&mallory)
        .to(&reputation_addr)
        .gas(20_000_000)
        .raw_call("append_response")
        .argument(&job_id_buf)
        .argument(&response_uri)
        .returns(ExpectError(
            4,
            "Only the agent owner can perform this action",
        ))
        .run()
        .await;
}
