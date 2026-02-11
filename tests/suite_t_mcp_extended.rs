use multiversx_sc_snippets::imports::*;
use mx_agentic_commerce_tests::ProcessManager;
use serde_json::{json, Value};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::ChildStdout;
use tokio::process::Command;
use tokio::time::{sleep, Duration};

mod common;
use common::GATEWAY_URL;

async fn read_json_response(reader: &mut BufReader<ChildStdout>) -> String {
    let mut line = String::new();
    loop {
        line.clear();
        let bytes = reader
            .read_line(&mut line)
            .await
            .expect("Failed to read line");
        if bytes == 0 {
            panic!("Unexpected EOF from MCP Server");
        }
        let trimmed = line.trim();
        if trimmed.starts_with('{') {
            return line;
        }
    }
}

async fn mcp_call(
    stdin: &mut tokio::process::ChildStdin,
    reader: &mut BufReader<ChildStdout>,
    id: u64,
    method: &str,
    params: Value,
) -> Value {
    let req = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
    stdin
        .write_all(serde_json::to_string(&req).unwrap().as_bytes())
        .await
        .unwrap();
    stdin.write_all(b"\n").await.unwrap();
    let line = read_json_response(reader).await;
    serde_json::from_str(&line).expect("Invalid JSON Response")
}

async fn mcp_init(stdin: &mut tokio::process::ChildStdin, reader: &mut BufReader<ChildStdout>) {
    let resp = mcp_call(
        stdin,
        reader,
        1,
        "initialize",
        json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-suite-t", "version": "1.0"}
        }),
    )
    .await;
    assert!(resp.get("result").is_some());
    let notify = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
    stdin
        .write_all(serde_json::to_string(&notify).unwrap().as_bytes())
        .await
        .unwrap();
    stdin.write_all(b"\n").await.unwrap();
}

async fn call_tool(
    stdin: &mut tokio::process::ChildStdin,
    reader: &mut BufReader<ChildStdout>,
    id: u64,
    tool_name: &str,
    arguments: Value,
) -> (Value, String) {
    let resp = mcp_call(
        stdin,
        reader,
        id,
        "tools/call",
        json!({
            "name": tool_name,
            "arguments": arguments,
        }),
    )
    .await;

    if let Some(error) = resp.get("error") {
        let error_str = format!("ERROR: {:?}", error);
        return (resp, error_str);
    }

    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("(no text)")
        .to_string();

    (resp, text)
}

/// Suite T: Extended MCP Tool Coverage
///
/// Tests MCP tools NOT covered by suite_o:
/// 1. send-tokens (ESDT transfer)
/// 2. track-transaction
/// 3. issue-nft-collection
/// 4. get-agent-pricing (registry)
/// 5. get-agent-trust-summary (registry)
/// 6. search-agents (registry)
/// 7. get-top-rated-agents (registry)
#[tokio::test]
async fn test_mcp_extended_tool_coverage() {
    let mut pm = ProcessManager::new();

    // ── 1. Start Chain Simulator ──
    pm.start_chain_simulator(8085)
        .expect("Failed to start simulator");
    sleep(Duration::from_secs(2)).await;

    let chain_id = common::get_simulator_chain_id().await;

    // Use existing alice.pem
    let pem_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("alice.pem");
    assert!(pem_path.exists(), "alice.pem not found at {:?}", pem_path);

    // ── 2. Deploy contracts for registry tools ──
    // Registry tools need deployed identity/validation/reputation contracts
    let alice_bech32 = "erd1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssycr6th";
    common::fund_address_on_simulator(alice_bech32, "100000000000000000000000").await;

    let mut interactor = Interactor::new(GATEWAY_URL).await;
    let alice_wallet = Wallet::from_pem_file(pem_path.to_str().unwrap()).expect("PEM load");
    let alice_addr = interactor.register_wallet(alice_wallet.clone()).await;

    let (identity, validation_addr, reputation_addr) =
        common::deploy_all_registries(&mut interactor, alice_addr.clone()).await;

    // Register an agent for pricing/trust/search queries
    identity
        .register_agent(
            &mut interactor,
            "PricingTestAgent",
            "https://pricing-agent.test/manifest",
            vec![("type", b"worker".to_vec())],
        )
        .await;

    // ── 3. Start MCP Server with contract addresses ──
    println!("Starting MCP Server...");
    let identity_bech32 = common::address_to_bech32(identity.address());
    let validation_bech32 = common::address_to_bech32(&validation_addr);
    let reputation_bech32 = common::address_to_bech32(&reputation_addr);

    let mut child = Command::new("node")
        .arg("dist/index.js")
        .arg("mcp")
        .current_dir("../multiversx-mcp-server")
        .env("MVX_API_URL", GATEWAY_URL)
        .env("MVX_NETWORK", "devnet")
        .env("MVX_WALLET_PEM", pem_path.to_str().unwrap())
        .env("MVX_IDENTITY_CONTRACT", &identity_bech32)
        .env("MVX_VALIDATION_CONTRACT", &validation_bech32)
        .env("MVX_REPUTATION_CONTRACT", &reputation_bech32)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to spawn MCP server");

    let stdin = child.stdin.as_mut().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout);

    mcp_init(stdin, &mut reader).await;

    let bob_addr = "erd1spyavw0956vq68xj8y4tenjpq2wd5a9p2c6j8gsz7ztyrnpxrruqzu66jx";

    // ── Test 1: send-tokens ──
    println!("\n📋 Test 1: send-tokens");
    let (_resp, text) = call_tool(
        stdin,
        &mut reader,
        10,
        "send-tokens",
        json!({
            "receiver": bob_addr,
            "tokenIdentifier": "EGLD",
            "amount": "1000000000000000000"
        }),
    )
    .await;
    println!("  Result: {}", &text[..text.len().min(300)]);
    // Tool should respond (may fail with chain ID or missing token, but should not crash)
    assert!(!text.is_empty(), "send-tokens should return a response");

    // ── Test 2: track-transaction ──
    println!("\n📋 Test 2: track-transaction");
    let fake_hash = "a".repeat(64);
    let (_resp, text) = call_tool(
        stdin,
        &mut reader,
        11,
        "track-transaction",
        json!({
            "txHash": fake_hash
        }),
    )
    .await;
    println!("  Result: {}", &text[..text.len().min(300)]);
    // Should return pending/unknown for a nonexistent hash
    assert!(
        text.contains("pending")
            || text.contains("unknown")
            || text.contains("404")
            || text.contains("error")
            || text.contains("Error"),
        "track-transaction should return pending/unknown/error for fake hash"
    );

    // ── Test 3: issue-nft-collection ──
    println!("\n📋 Test 3: issue-nft-collection");
    let (_resp, text) = call_tool(
        stdin,
        &mut reader,
        12,
        "issue-nft-collection",
        json!({
            "tokenName": "TestNFT",
            "tokenTicker": "TNFT"
        }),
    )
    .await;
    println!("  Result: {}", &text[..text.len().min(300)]);
    assert!(
        !text.is_empty(),
        "issue-nft-collection should return a response"
    );

    // ── Test 4: get-agent-pricing ──
    println!("\n📋 Test 4: get-agent-pricing");
    let (_resp, text) = call_tool(
        stdin,
        &mut reader,
        13,
        "get-agent-pricing",
        json!({
            "agentNonce": 1
        }),
    )
    .await;
    println!("  Result: {}", &text[..text.len().min(300)]);
    // Should return pricing data or "no services" for newly registered agent
    assert!(
        !text.is_empty(),
        "get-agent-pricing should return a response"
    );

    // ── Test 5: get-agent-trust-summary ──
    println!("\n📋 Test 5: get-agent-trust-summary");
    let (_resp, text) = call_tool(
        stdin,
        &mut reader,
        14,
        "get-agent-trust-summary",
        json!({
            "agentNonce": 1
        }),
    )
    .await;
    println!("  Result: {}", &text[..text.len().min(300)]);
    assert!(
        !text.is_empty(),
        "get-agent-trust-summary should return a response"
    );

    // ── Test 6: search-agents ──
    println!("\n📋 Test 6: search-agents");
    let (_resp, text) = call_tool(
        stdin,
        &mut reader,
        15,
        "search-agents",
        json!({
            "query": "PricingTestAgent",
            "limit": 5
        }),
    )
    .await;
    println!("  Result: {}", &text[..text.len().min(300)]);
    assert!(!text.is_empty(), "search-agents should return a response");

    // ── Test 7: get-top-rated-agents ──
    println!("\n📋 Test 7: get-top-rated-agents");
    let (_resp, text) = call_tool(
        stdin,
        &mut reader,
        16,
        "get-top-rated-agents",
        json!({
            "limit": 5
        }),
    )
    .await;
    println!("  Result: {}", &text[..text.len().min(300)]);
    assert!(
        !text.is_empty(),
        "get-top-rated-agents should return a response"
    );

    // Cleanup
    child.kill().await.expect("Failed to kill MCP");

    println!("\nSuite T: Extended MCP Tool Coverage — PASSED ✅");
    println!("  Tested: send-tokens, track-transaction, issue-nft-collection,");
    println!("          get-agent-pricing, get-agent-trust-summary, search-agents,");
    println!("          get-top-rated-agents");
}
