use crate::common::{
    create_pem_file, fund_address_on_simulator_custom, generate_random_private_key,
    IdentityRegistryInteractor,
};
use identity_registry_interactor::identity_registry_proxy::IdentityRegistryProxy;
use multiversx_sc::types::{ManagedBuffer, TokenIdentifier};
use multiversx_sc_snippets::imports::*;
use mx_agentic_commerce_tests::ProcessManager;
use tokio::time::{sleep, Duration};

const GATEWAY_URL: &str = "http://localhost:8087";

#[tokio::test]
async fn test_metadata_ops() {
    let mut pm = ProcessManager::new();
    pm.start_chain_simulator(8087)
        .expect("Failed to start simulator");
    sleep(Duration::from_secs(2)).await;

    let mut interactor = Interactor::new(GATEWAY_URL).await.use_chain_simulator(true);

    let alice_private_key = generate_random_private_key();
    let alice_wallet = Wallet::from_private_key(&alice_private_key).unwrap();
    let alice_address = alice_wallet.to_address();
    create_pem_file(
        "alice_meta.pem",
        &alice_private_key,
        &alice_address.to_bech32("erd").to_string(),
    );

    interactor.register_wallet(alice_wallet.clone()).await;
    let wallet_bech32 = alice_address.to_bech32("erd").to_string();
    fund_address_on_simulator_custom(&wallet_bech32, "100000000000000000000000", GATEWAY_URL).await;

    let mut identity_interactor =
        IdentityRegistryInteractor::init(&mut interactor, alice_address.clone()).await;
    identity_interactor
        .issue_token(&mut interactor, "AgentToken", "AGENT")
        .await;
    identity_interactor
        .register_agent(&mut interactor, "BotMeta", "uri", vec![])
        .await;

    let address = identity_interactor.address().clone();

    let token_id: TokenIdentifier<StaticApi> = interactor
        .query()
        .to(&address)
        .typed(IdentityRegistryProxy)
        .agent_token_id()
        .returns(ReturnsResult)
        .run()
        .await;
    let token_str = token_id.to_string();

    // 1. Set Metadata (3 items)
    let meta1 = vec![
        ("key1", b"val1".to_vec()),
        ("key2", b"val2".to_vec()),
        ("key3", b"val3".to_vec()),
    ];
    identity_interactor
        .set_metadata(&mut interactor, meta1, &token_str, 1)
        .await;

    // Verify key1
    let val1_opt: OptionalValue<ManagedBuffer<StaticApi>> = interactor
        .query()
        .to(&address)
        .typed(IdentityRegistryProxy)
        .get_metadata(1u64, ManagedBuffer::new_from_bytes(b"key1"))
        .returns(ReturnsResult)
        .run()
        .await;
    assert_eq!(val1_opt.into_option().unwrap().to_vec(), b"val1");

    // 2. Overwrite key2
    let meta2 = vec![("key2", b"val2_updated".to_vec())];
    identity_interactor
        .set_metadata(&mut interactor, meta2, &token_str, 1)
        .await;

    let val2_opt: OptionalValue<ManagedBuffer<StaticApi>> = interactor
        .query()
        .to(&address)
        .typed(IdentityRegistryProxy)
        .get_metadata(1u64, ManagedBuffer::new_from_bytes(b"key2"))
        .returns(ReturnsResult)
        .run()
        .await;
    assert_eq!(val2_opt.into_option().unwrap().to_vec(), b"val2_updated");

    // 3. Remove key3
    identity_interactor
        .remove_metadata(&mut interactor, vec!["key3"], &token_str, 1)
        .await;

    let val3_opt: OptionalValue<ManagedBuffer<StaticApi>> = interactor
        .query()
        .to(&address)
        .typed(IdentityRegistryProxy)
        .get_metadata(1u64, ManagedBuffer::new_from_bytes(b"key3"))
        .returns(ReturnsResult)
        .run()
        .await;
    assert!(val3_opt.into_option().is_none());

    // key1 should still exist
    let val1_check: OptionalValue<ManagedBuffer<StaticApi>> = interactor
        .query()
        .to(&address)
        .typed(IdentityRegistryProxy)
        .get_metadata(1u64, ManagedBuffer::new_from_bytes(b"key1"))
        .returns(ReturnsResult)
        .run()
        .await;
    assert!(val1_check.into_option().is_some());
}
