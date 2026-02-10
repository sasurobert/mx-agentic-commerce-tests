use crate::common::{
    fund_address_on_simulator, generate_blocks_on_simulator, generate_random_private_key,
    get_simulator_chain_id, issue_fungible_esdt, GATEWAY_URL,
};
use multiversx_sc::types::Address;
use multiversx_sc_snippets::imports::*;
use mx_agentic_commerce_tests::ProcessManager;
use std::process::Command;
use tokio::time::{sleep, Duration};

const FACILITATOR_PORT: u16 = 3046;

#[tokio::test]
async fn test_settle_esdt() {
    let mut pm = ProcessManager::new();
    let _ = pm.start_chain_simulator(8085);
    sleep(Duration::from_secs(2)).await;

    let mut interactor = Interactor::new(GATEWAY_URL).await.use_chain_simulator(true);

    let sender_pk = generate_random_private_key();
    let sender_wallet = Wallet::from_private_key(&sender_pk).unwrap();
    let sender_address = sender_wallet.to_address().to_bech32("erd").to_string();
    let sender_sc_address = interactor.register_wallet(sender_wallet).await;

    let receiver_pk = generate_random_private_key();
    let receiver_wallet = Wallet::from_private_key(&receiver_pk).unwrap();
    let receiver_address = receiver_wallet.to_address().to_bech32("erd").to_string();

    // 1. Fund Sender (needs EGLD for issuance fees + gas)
    println!("Funding Sender: {}", sender_address);
    fund_address_on_simulator(&sender_address, "500000000000000000000").await; // 500 EGLD

    // 2. Issue ESDT
    let token_id = issue_fungible_esdt(
        &mut interactor,
        &sender_sc_address,
        "TestToken",
        "TEST",
        1_000_000_000_000_000_000,
        6,
    )
    .await;
    println!("Issued Token: {}", token_id);

    // 3. Start Facilitator
    let facilitator_port = FACILITATOR_PORT;
    let db_path = "./facilitator_esdt.db";
    let _ = std::fs::remove_file(db_path);

    let _facilitator_process = Command::new("npx")
        .arg("ts-node")
        .arg("../x402_integration/x402_facilitator/src/index.ts")
        .env("PORT", facilitator_port.to_string())
        .env("PRIVATE_KEY", generate_random_private_key())
        .env(
            "REGISTRY_ADDRESS",
            "erd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gq4hu",
        )
        .env("NETWORK_PROVIDER", GATEWAY_URL)
        .env("GATEWAY_URL", GATEWAY_URL)
        .env("CHAIN_ID", get_simulator_chain_id().await)
        .env("SQLITE_DB_PATH", db_path)
        .env("SKIP_SIMULATION", "false")
        .spawn()
        .expect("Failed to start facilitator");

    // Give it time to start
    let client = reqwest::Client::new();
    let facilitator_url = format!("http://localhost:{}", facilitator_port);
    for _ in 0..10 {
        if client
            .get(format!("{}/health", facilitator_url))
            .send()
            .await
            .is_ok()
        {
            break;
        }
        sleep(Duration::from_millis(500)).await;
    }

    // 4. Sign ESDT Transaction
    let chain_id = get_simulator_chain_id().await;
    let esdt_amount = "1000000"; // 1.000000 USDC

    // Use the updated sign_tx.ts with --token and --amount
    let output = Command::new("npx")
        .arg("ts-node")
        .arg("../moltbot-starter-kit/scripts/sign_tx.ts")
        .arg("--sender-pk")
        .arg(&sender_pk)
        .arg("--receiver")
        .arg(&receiver_address)
        .arg("--value")
        .arg("0") // EGLD value is 0 for ESDT transfer
        .arg("--token")
        .arg(&token_id)
        .arg("--amount")
        .arg(esdt_amount)
        .arg("--nonce")
        .arg("1") // Nonce 1 (0 was issuance)
        .arg("--gas-limit")
        .arg("500000") // ESDT transfer needs more gas
        .arg("--gas-price")
        .arg("1000000000")
        .arg("--chain-id")
        .arg(&chain_id)
        .output()
        .expect("Failed to sign transaction");

    if !output.status.success() {
        eprintln!("Sign Tx Error: {}", String::from_utf8_lossy(&output.stderr));
        panic!("Sign Tx failed");
    }

    let json_str = String::from_utf8(output.stdout).unwrap();
    let signed_tx: serde_json::Value = serde_json::from_str(json_str.trim()).unwrap();
    println!("Signed Tx Payload: {}", signed_tx);

    // 4.5 Call /verify
    let verify_resp = client
        .post(format!("{}/verify", facilitator_url))
        .json(&signed_tx)
        .send()
        .await
        .expect("Failed to call verify");

    if !verify_resp.status().is_success() {
        let status = verify_resp.status();
        let body = verify_resp.text().await.unwrap_or_default();
        panic!("Facilitator verify failed: {} - {}", status, body);
    }

    let verify_json: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(verify_json["isValid"], true, "Tx should be valid");

    // 5. Call /settle
    let resp = client
        .post(format!("{}/settle", facilitator_url))
        .json(&signed_tx)
        .send()
        .await
        .expect("Failed to call settle");

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        panic!("Facilitator settle failed: {} - {}", status, body);
    }

    let resp_json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(resp_json["success"], true);

    // 6. Generate Blocks & Verify
    // Wait for facilitator to broadcast
    sleep(Duration::from_secs(2)).await;
    generate_blocks_on_simulator(5).await;
    sleep(Duration::from_secs(5)).await;

    // Check Receiver ESDT Balance
    let account_url = format!(
        "{}/address/{}/esdt/{}",
        GATEWAY_URL, receiver_address, token_id
    );
    let balance_resp = client
        .get(&account_url)
        .send()
        .await
        .expect("Failed to get balance");

    if !balance_resp.status().is_success() {
        panic!("Receiver has no token balance (404 likely)");
    }

    let balance_json: serde_json::Value = balance_resp.json().await.unwrap();
    let balance = balance_json["data"]["tokenData"]["balance"]
        .as_str()
        .unwrap();

    assert_eq!(balance, esdt_amount, "Receiver ESDT balance incorrect");
}
