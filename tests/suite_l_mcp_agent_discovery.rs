use multiversx_sc_snippets::imports::*;
use mx_agentic_commerce_tests::ProcessManager;
use serde_json::{json, Value};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::ChildStdout;
use tokio::process::Command;
use tokio::time::{sleep, Duration};

mod common;
use common::{IdentityRegistryInteractor, GATEWAY_URL};

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
        println!("Ignored Log: {}", trimmed);
    }
}

/// Helper: send a JSON-RPC request and read the response
async fn mcp_call(
    stdin: &mut tokio::process::ChildStdin,
    reader: &mut BufReader<ChildStdout>,
    id: u64,
    method: &str,
    params: Value,
) -> Value {
    let req = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    });
    let req_str = serde_json::to_string(&req).unwrap();
    stdin.write_all(req_str.as_bytes()).await.unwrap();
    stdin.write_all(b"\n").await.unwrap();

    let line = read_json_response(reader).await;
    let resp: Value = serde_json::from_str(&line).expect("Invalid JSON Response");
    if let Some(error) = resp.get("error") {
        panic!("MCP call '{}' failed: {:?}", method, error);
    }
    resp
}

/// Helper: initialize MCP server connection
async fn mcp_init(stdin: &mut tokio::process::ChildStdin, reader: &mut BufReader<ChildStdout>) {
    // Initialize
    let resp = mcp_call(
        stdin,
        reader,
        1,
        "initialize",
        json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-suite", "version": "1.0"}
        }),
    )
    .await;
    assert!(resp.get("result").is_some(), "MCP init failed");

    // Send initialized notification (no response expected)
    let notify = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    stdin
        .write_all(serde_json::to_string(&notify).unwrap().as_bytes())
        .await
        .unwrap();
    stdin.write_all(b"\n").await.unwrap();
}

/// Suite L: MCP Agent Discovery E2E
///
/// Registers agents on-chain via Rust interactor, then verifies
/// they are discoverable through MCP tools.
#[tokio::test]
async fn test_mcp_agent_discovery() {
    let mut pm = ProcessManager::new();

    // ── 1. Start Chain Simulator ──
    pm.start_chain_simulator(8085)
        .expect("Failed to start simulator");
    sleep(Duration::from_secs(2)).await;

    // ── 2. Deploy Identity Registry & Register Agents ──
    let mut interactor = Interactor::new(GATEWAY_URL).await.use_chain_simulator(true);
    let wallet_alice = interactor.register_wallet(test_wallets::alice()).await;

    let mut identity =
        IdentityRegistryInteractor::init(&mut interactor, wallet_alice.clone()).await;
    identity.issue_token("AgentToken", "AGENT").await;

    // Register Agent #1 with metadata
    identity.register_agent(
        "AlphaBot",
        "data:application/json;base64,eyJuYW1lIjoiQWxwaGFCb3QiLCJjYXBhYmlsaXRpZXMiOlsiY2hhdCIsInZpc2lvbiJdfQ==",
        vec![
            ("category", b"shopping".to_vec()),
            ("version", b"1.0".to_vec()),
        ],
    ).await;

    // Register Agent #2
    identity
        .register_agent(
            "BetaBot",
            "https://betabot.example.com/manifest.json",
            vec![("category", b"finance".to_vec())],
        )
        .await;

    let chain_id = common::get_simulator_chain_id().await;
    let registry_address = common::address_to_bech32(identity.address());
    println!("Registry Address: {}", registry_address);

    // ── 3. Start MCP Server ──
    println!("Starting MCP Server...");
    let mut child = Command::new("node")
        .arg("dist/index.js")
        .arg("mcp")
        .current_dir("../multiversx-mcp-server")
        .env("MULTIVERSX_API_URL", GATEWAY_URL)
        .env("MULTIVERSX_CHAIN_ID", &chain_id)
        .env("IDENTITY_REGISTRY_ADDRESS", &registry_address)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to spawn MCP server");

    let stdin = child.stdin.as_mut().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut reader = BufReader::new(stdout);

    mcp_init(stdin, &mut reader).await;

    // ── 4. Test get-agent-manifest for Agent #1 ──
    println!("Testing get-agent-manifest for Agent #1...");
    let resp = mcp_call(
        stdin,
        &mut reader,
        10,
        "tools/call",
        json!({
            "name": "get-agent-manifest",
            "arguments": { "agentNonce": 1 }
        }),
    )
    .await;

    let content = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("No text in manifest response");
    println!("Agent #1 Manifest: {}", content);

    // Parse and verify
    let manifest: Value =
        serde_json::from_str(content).expect("Manifest content is not valid JSON");
    assert_eq!(
        manifest["name"].as_str().unwrap(),
        "AlphaBot",
        "Agent name mismatch"
    );
    assert!(
        manifest["uri"].as_str().unwrap().contains("AlphaBot"),
        "URI should contain agent data"
    );

    // ── 5. Test get-agent-manifest for Agent #2 ──
    println!("Testing get-agent-manifest for Agent #2...");
    let resp = mcp_call(
        stdin,
        &mut reader,
        11,
        "tools/call",
        json!({
            "name": "get-agent-manifest",
            "arguments": { "agentNonce": 2 }
        }),
    )
    .await;

    let content = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("No text in manifest response");
    println!("Agent #2 Manifest: {}", content);
    let manifest: Value =
        serde_json::from_str(content).expect("Manifest content is not valid JSON");
    assert_eq!(
        manifest["name"].as_str().unwrap(),
        "BetaBot",
        "Agent #2 name mismatch"
    );

    // ── 6. Cleanup ──
    child.kill().await.expect("Failed to kill MCP server");
    println!("Suite L: MCP Agent Discovery — PASSED ✅");
}
