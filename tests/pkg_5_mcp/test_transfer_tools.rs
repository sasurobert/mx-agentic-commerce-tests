use crate::common::{
    address_to_bech32, fund_address_on_simulator, generate_random_private_key,
    get_simulator_chain_id, GATEWAY_URL,
};
use base64::Engine;
use multiversx_sc_snippets::imports::*;
use mx_agentic_commerce_tests::ProcessManager;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_transfer_tools() {
    let mut pm = ProcessManager::new();
    pm.start_chain_simulator(8085)
        .expect("Failed to start simulator");
    sleep(Duration::from_secs(2)).await;

    let chain_id = get_simulator_chain_id().await;
    let mut interactor = Interactor::new(GATEWAY_URL).await.use_chain_simulator(true);

    // CRITICAL: Activate all protocol features (including ESDT System SC)
    // Without this, ESDT issuance fails with "ESDT SC disabled"
    interactor.generate_blocks_until_all_activations().await;

    // 1. Setup Sender (Alice)
    let alice_pk_hex = generate_random_private_key();
    let alice_wallet = Wallet::from_private_key(&alice_pk_hex).unwrap();
    let alice_addr = alice_wallet.to_address();
    let alice_bech32 = address_to_bech32(&alice_addr);

    // Fund Alice
    fund_address_on_simulator(&alice_bech32, "200000000000000000000").await; // 200 EGLD

    // 2. Create PEM file manually (Hex -> Base64 for SDK)
    let temp_pem_path = std::env::current_dir()
        .unwrap()
        .join("tests/pkg_5_mcp/alice_transfer.pem");
    if let Some(parent) = temp_pem_path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }

    let alice_pk_bytes = hex::decode(&alice_pk_hex).unwrap();
    let alice_pub_bytes = alice_addr.as_bytes();

    // Construct 64-byte key (Secret + Public)
    let mut full_key = Vec::new();
    full_key.extend_from_slice(&alice_pk_bytes);
    full_key.extend_from_slice(alice_pub_bytes);

    // SDK expects Base64(Hex(KeyBytes)) based on pem.js inspection
    let hex_key = hex::encode(&full_key);
    let base64_sk = base64::engine::general_purpose::STANDARD.encode(hex_key);

    let pem_content = format!(
        "-----BEGIN PRIVATE KEY for {}-----\n{}\n-----END PRIVATE KEY for {}-----",
        alice_bech32, base64_sk, alice_bech32
    );
    std::fs::write(&temp_pem_path, pem_content).unwrap();

    // 3. Start MCP with Wallet
    let mut client =
        crate::mcp_client::McpClient::new(&chain_id, Some(temp_pem_path.to_str().unwrap())).await;

    // 4. Test send-egld
    println!("Testing send-egld...");
    let bob_pk = generate_random_private_key();
    let bob_wallet = Wallet::from_private_key(&bob_pk).unwrap();
    let bob_bech32 = address_to_bech32(&bob_wallet.to_address());

    let args = serde_json::json!({
        "receiver": bob_bech32,
        "amount": "1000000000000000000" // 1 EGLD
    });

    let resp = client.call_tool("send-egld", args).await;

    if let Some(err) = resp.get("error") {
        panic!("MCP Error: {:?} Content: {:?}", err, resp.get("result"));
    }

    let result = &resp["result"];
    let content = result["content"].as_array().unwrap();
    if let Some(text_block) = content.iter().find(|c| c["type"] == "text") {
        let text = text_block["text"].as_str().unwrap();
        println!("Send EGLD Output: {}", text);
        assert!(
            text.contains("Transaction sent"),
            "Output should confirm transaction sent"
        );
    } else {
        panic!("No text content in response");
    }

    // Verify Bob received funds
    let client_http = reqwest::Client::new();
    let mut balance_found = false;
    for _ in 0..10 {
        let bob_acc_resp = client_http
            .get(format!("{}/address/{}", GATEWAY_URL, bob_bech32))
            .send()
            .await;
        if let Ok(r) = bob_acc_resp {
            if let Ok(json) = r.json::<serde_json::Value>().await {
                if let Some(bal) = json["data"]["account"]["balance"].as_str() {
                    if bal == "1000000000000000000" {
                        balance_found = true;
                        break;
                    }
                }
            }
        }
        interactor.generate_blocks(1).await;
        sleep(Duration::from_millis(500)).await;
    }
    assert!(balance_found, "Bob should have 1 EGLD");

    // 5. Issue Fungible Token via MCP Tool
    println!("Testing issue-fungible-token...");
    let random_suffix = rand::random::<u32>() % 10000;
    let ticker = format!("TEST{}", random_suffix);
    let name = format!("TestToken{}", random_suffix);

    let issue_args = serde_json::json!({
        "tokenName": name,
        "tokenTicker": ticker,
        "initialSupply": "1000000",
        "numDecimals": 6
    });

    let issue_resp = client.call_tool("issue-fungible-token", issue_args).await;
    if let Some(err) = issue_resp.get("error") {
        panic!("MCP Error: {:?}", err);
    }

    let issue_text = issue_resp["result"]["content"][0]["text"].as_str().unwrap();
    println!("Issue Token Output: {}", issue_text);
    assert!(issue_text.contains("Token issuance transaction sent"));

    // Extract tx hash from output
    let parts: Vec<&str> = issue_text.split("transactions/").collect();
    let hash_part = parts
        .get(1)
        .unwrap_or(&"")
        .split_whitespace()
        .next()
        .unwrap_or("");
    let tx_hash = hash_part.trim_matches(|c: char| !c.is_alphanumeric());
    println!("Extracted Tx Hash: '{}'", tx_hash);

    // Generate blocks & poll for token
    let mut token_id = String::new();
    let alice_esdt_url = format!("{}/address/{}/esdt", GATEWAY_URL, alice_bech32);

    for i in 0..20 {
        interactor.generate_blocks(1).await;
        sleep(Duration::from_millis(500)).await;

        let resp_esdt = client_http.get(&alice_esdt_url).send().await;
        if let Ok(r) = resp_esdt {
            if let Ok(json) = r.json::<serde_json::Value>().await {
                if let Some(esdts) = json["data"]["esdts"].as_object() {
                    println!("Poll {} Found ESDTs: {:?}", i, esdts.keys());
                    if let Some((id, _)) = esdts.iter().find(|(k, _)| k.starts_with(&ticker)) {
                        token_id = id.clone();
                        break;
                    }
                }
            }
        }
    }

    if token_id.is_empty() {
        // Fetch tx result for debugging
        let tx_url = format!("{}/transaction/{}?withResults=true", GATEWAY_URL, tx_hash);
        let tx_resp = client_http.get(&tx_url).send().await;
        if let Ok(r) = tx_resp {
            if let Ok(json) = r.json::<serde_json::Value>().await {
                println!("DEBUG Tx Result: {:#}", json);
            }
        }
        panic!(
            "Failed to find issued token {} for address {}",
            ticker, alice_bech32
        );
    }
    println!("Found Token ID: {}", token_id);

    // 6. Test send-tokens (ESDT)
    println!("Testing send-tokens...");
    let args_token = serde_json::json!({
        "receiver": bob_bech32,
        "tokenIdentifier": token_id,
        "amount": "100"
    });

    let resp_token = client.call_tool("send-tokens", args_token).await;
    if let Some(err) = resp_token.get("error") {
        panic!("MCP Error: {:?}", err);
    }

    let text_token_res = resp_token["result"]["content"][0]["text"].as_str().unwrap();
    println!("Send Token Output: {}", text_token_res);
    assert!(text_token_res.contains("Transaction sent"));

    // Verify Bob token balance
    let bob_esdt_url = format!("{}/address/{}/esdt/{}", GATEWAY_URL, bob_bech32, token_id);

    let mut token_found = false;
    for _ in 0..15 {
        let resp_esdt = client_http.get(&bob_esdt_url).send().await.unwrap();
        if resp_esdt.status().is_success() {
            let json: serde_json::Value = resp_esdt.json().await.unwrap();
            if let Some(token_data) = json.get("data").and_then(|d| d.get("tokenData")) {
                let balance = token_data["balance"].as_str().unwrap_or("0");
                if balance == "100" {
                    token_found = true;
                    break;
                }
            }
        }
        interactor.generate_blocks(1).await;
        sleep(Duration::from_millis(500)).await;
    }
    assert!(token_found, "Bob should have 100 tokens");

    // Cleanup
    let _ = std::fs::remove_file(temp_pem_path);
}
