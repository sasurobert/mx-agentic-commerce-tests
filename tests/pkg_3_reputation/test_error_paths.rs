use multiversx_sc::types::ManagedBuffer;
use multiversx_sc_snippets::imports::*;
use mx_agentic_commerce_tests::ProcessManager;
use tokio::time::{sleep, Duration};

use crate::common::{address_to_bech32, deploy_all_registries, fund_address_on_simulator};

const GATEWAY_PORT: u16 = 8085;
const GATEWAY_URL: &str = "http://localhost:8085";

async fn setup_env() -> (Interactor, Address, Address, Address, Address) {
    // interactor, rep_addr, val_addr, owner, employer
    let mut pm = ProcessManager::new();
    pm.start_chain_simulator(GATEWAY_PORT)
        .expect("Failed to start simulator");
    sleep(Duration::from_secs(2)).await;

    let mut interactor = Interactor::new(GATEWAY_URL).await.use_chain_simulator(true);
    let owner = interactor.register_wallet(test_wallets::alice()).await;
    fund_address_on_simulator(&address_to_bech32(&owner), "100000000000000000000").await;

    let employer = interactor.register_wallet(test_wallets::bob()).await;
    fund_address_on_simulator(&address_to_bech32(&employer), "100000000000000000000").await;

    let (mut identity, validation_addr, reputation_addr) =
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
        interactor,
        reputation_addr,
        validation_addr,
        owner,
        employer,
    )
}

#[tokio::test]
#[should_panic(expected = "Caller is not the agent owner")]
async fn test_authorize_feedback_non_owner() {
    let (mut interactor, reputation_addr, _, _, employer) = setup_env().await;
    let mallory = interactor.register_wallet(test_wallets::carol()).await;
    fund_address_on_simulator(&address_to_bech32(&mallory), "100000000000000000000").await;

    let job_id_buf = ManagedBuffer::<StaticApi>::new_from_bytes(b"job-rep-err");
    let employer_buf = ManagedBuffer::<StaticApi>::new_from_bytes(employer.as_bytes());

    interactor
        .tx()
        .from(&mallory)
        .to(&reputation_addr)
        .gas(20_000_000)
        .raw_call("authorize_feedback")
        .argument(&job_id_buf)
        .argument(&employer_buf)
        .run()
        .await;
}

#[tokio::test]
#[should_panic(expected = "Feedback not authorized")]
async fn test_submit_feedback_unauthorized() {
    let (mut interactor, reputation_addr, _, _, employer) = setup_env().await;

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
        .run()
        .await;
}
