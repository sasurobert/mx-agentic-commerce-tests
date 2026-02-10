use multiversx_sc::types::{BigUint, EgldOrEsdtTokenIdentifier, ManagedBuffer};
use multiversx_sc_snippets::imports::*;
use mx_agentic_commerce_tests::ProcessManager;
use tokio::time::{sleep, Duration};

use crate::common::{
    address_to_bech32, deploy_all_registries, fund_address_on_simulator, ServiceConfigInput,
    GATEWAY_URL,
};

const GATEWAY_PORT: u16 = 8085;

async fn setup_env() -> (ProcessManager, Interactor, Address, Address, Address) {
    let mut pm = ProcessManager::new();
    pm.start_chain_simulator(GATEWAY_PORT)
        .expect("Failed to start simulator");
    sleep(Duration::from_secs(2)).await;

    let mut interactor = Interactor::new(GATEWAY_URL).await.use_chain_simulator(true);
    let owner = interactor.register_wallet(test_wallets::alice()).await;
    fund_address_on_simulator(&address_to_bech32(&owner), "100000000000000000000").await;

    let (mut identity, validation_addr, _) =
        deploy_all_registries(&mut interactor, owner.clone()).await;

    let service = ServiceConfigInput::<StaticApi> {
        service_id: 1,
        price: BigUint::<StaticApi>::from(1_000_000_000_000_000_000u64), // 1 EGLD
        token: EgldOrEsdtTokenIdentifier::<StaticApi>::egld(),
        nonce: 0,
    };
    identity
        .register_agent_with_services(&mut interactor, "PayBot", "uri", vec![], vec![service])
        .await;

    (
        pm,
        interactor,
        validation_addr,
        identity.address().clone(),
        owner,
    )
}

#[tokio::test]
#[should_panic(expected = "Insufficient payment")]
async fn test_init_job_insufficient_payment() {
    let (_pm, mut interactor, validation_addr, _, _) = setup_env().await;
    let employer = interactor.register_wallet(test_wallets::bob()).await;
    fund_address_on_simulator(&address_to_bech32(&employer), "100000000000000000000").await;

    interactor
        .tx()
        .from(&employer)
        .to(&validation_addr)
        .gas(20_000_000)
        .egld(500_000_000_000_000_000u64) // 0.5 EGLD
        .raw_call("init_job")
        .argument(&ManagedBuffer::<StaticApi>::new_from_bytes(b"job-fail-1"))
        .argument(&1u64) // agent_nonce
        .argument(&1u32) // service_id
        .run()
        .await;
}

#[tokio::test]
#[should_panic(expected = "Job already initialized")]
async fn test_init_job_duplicate_id() {
    let (_pm, mut interactor, validation_addr, _, _) = setup_env().await;
    let employer = interactor.register_wallet(test_wallets::bob()).await;
    fund_address_on_simulator(&address_to_bech32(&employer), "100000000000000000000").await;

    // First init (success)
    interactor
        .tx()
        .from(&employer)
        .to(&validation_addr)
        .gas(20_000_000)
        .raw_call("init_job")
        .argument(&ManagedBuffer::<StaticApi>::new_from_bytes(b"job-dup"))
        .argument(&1u64)
        .run()
        .await;

    // Second init (fail)
    interactor
        .tx()
        .from(&employer)
        .to(&validation_addr)
        .gas(20_000_000)
        .raw_call("init_job")
        .argument(&ManagedBuffer::<StaticApi>::new_from_bytes(b"job-dup"))
        .argument(&1u64)
        .run()
        .await;
}
