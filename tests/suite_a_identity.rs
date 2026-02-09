use identity_registry_interactor::identity_registry_proxy::IdentityRegistryProxy;
use multiversx_sc_scenario::imports::InterpreterContext;
use multiversx_sc_snippets::imports::StaticApi;
use multiversx_sc_snippets::imports::*;
use mx_agentic_commerce_tests::ProcessManager;
use tokio::time::{sleep, Duration};

#[path = "common/mod.rs"]
mod test_utils;
use ::common::{MetadataEntry, ServiceConfigInput};
use test_utils::GATEWAY_URL;

#[tokio::test]
async fn test_identity_registry_flow() {
    let mut pm = ProcessManager::new();
    pm.start_chain_simulator(8085)
        .expect("Failed to start simulator");

    sleep(Duration::from_secs(2)).await;

    let mut interactor = Interactor::new(GATEWAY_URL).await.use_chain_simulator(true);
    let mut interactor = Interactor::new(GATEWAY_URL).await.use_chain_simulator(true);

    let wallet_alice = interactor.register_wallet(test_wallets::alice()).await;

    interactor.generate_blocks_until_all_activations().await;

    println!("Identity Registry Flow Test Started");

    // Deploy using mxsc.json pattern from working interactor
    let mut mxsc_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    mxsc_path.push("artifacts");
    mxsc_path.push("identity-registry.mxsc.json");

    // Check if file exists to avoid confusing error
    if !mxsc_path.exists() {
        panic!("MXSC JSON not found at: {:?}", mxsc_path);
    }

    println!("Loading MXSC from: {:?}", mxsc_path);

    let contract_code = BytesValue::interpret_from(
        format!("mxsc:{}", mxsc_path.to_str().unwrap()),
        &InterpreterContext::default(),
    );

    let new_address = interactor
        .tx()
        .from(&wallet_alice)
        .gas(100_000_000)
        .typed(IdentityRegistryProxy)
        .init()
        .code(&contract_code)
        .returns(ReturnsNewAddress)
        .run()
        .await;

    println!("Deployed at: {}", new_address.to_bech32_default());

    // Issue Token
    interactor
        .tx()
        .from(&wallet_alice)
        .to(&new_address)
        .gas(60_000_000)
        .typed(IdentityRegistryProxy)
        .issue_token(
            ManagedBuffer::new_from_bytes(b"AgentToken"),
            ManagedBuffer::new_from_bytes(b"AGENT"),
        )
        .egld(50_000_000_000_000_000u64)
        .run()
        .await;

    println!("Issued Token");

    // Prepare Metadata
    let mut metadata_entries = MultiValueEncodedCounted::new();
    let price: u64 = 1_000_000_000_000_000_000;

    let entry1 = MetadataEntry {
        key: ManagedBuffer::<StaticApi>::new_from_bytes(b"price:default"),
        value: ManagedBuffer::<StaticApi>::new_from_bytes(&price.to_be_bytes()),
    };
    metadata_entries.push(entry1);

    let entry2 = MetadataEntry {
        key: ManagedBuffer::<StaticApi>::new_from_bytes(b"token:default"),
        value: ManagedBuffer::<StaticApi>::new_from_bytes(b"EGLD"),
    };
    metadata_entries.push(entry2);

    // Register Agent
    interactor
        .tx()
        .from(&wallet_alice)
        .to(&new_address)
        .gas(60_000_000)
        .typed(IdentityRegistryProxy)
        .register_agent(
            ManagedBuffer::new_from_bytes(b"MyAgent"),
            ManagedBuffer::new_from_bytes(b"https://example.com/agent.json"),
            ManagedBuffer::new_from_bytes(&[0u8; 32]), // dummy pk
            metadata_entries,
            MultiValueEncodedCounted::<StaticApi, ServiceConfigInput<StaticApi>>::new(),
        )
        .run()
        .await;

    println!("Registered Agent");

    sleep(Duration::from_secs(1)).await;
}
