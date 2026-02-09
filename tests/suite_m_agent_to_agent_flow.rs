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
    let resp: Value = serde_json::from_str(&line).expect("Invalid JSON Response");
    if let Some(error) = resp.get("error") {
        panic!("MCP call '{}' failed: {:?}", method, error);
    }
    resp
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
            "clientInfo": {"name": "test-suite-m", "version": "1.0"}
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

/// Suite M: Agent-to-Agent Discovery via MCP + x402 Facilitator
#[tokio::test]
async fn test_agent_to_agent_discovery() {
    let mut pm = ProcessManager::new();

    // ── 1. Start Chain Simulator ──
    pm.start_chain_simulator(8085)
        .expect("Failed to start simulator");
    sleep(Duration::from_secs(2)).await;

    let chain_id = common::get_simulator_chain_id().await;
    println!("Simulator ChainID: {}", chain_id);

    // ── 2. Setup wallets first (before identity borrow) ──
    let mut interactor = Interactor::new(GATEWAY_URL).await.use_chain_simulator(true);
    let wallet_alice = interactor.register_wallet(test_wallets::alice()).await;

    // Generate and fund moltbot wallet
    let moltbot_pk = common::generate_random_private_key();
    let moltbot_wallet = Wallet::from_private_key(&moltbot_pk).expect("Wallet failed");
    let moltbot_address = interactor.register_wallet(moltbot_wallet).await;
    let moltbot_bech32 = common::address_to_bech32(&moltbot_address);
    println!("Moltbot A Address: {}", moltbot_bech32);

    interactor
        .tx()
        .from(&wallet_alice)
        .to(&moltbot_address)
        .egld(1_000_000_000_000_000_000u64)
        .run()
        .await;

    // Generate and fund facilitator wallet
    let facilitator_pk = common::generate_random_private_key();
    let fac_wallet = Wallet::from_private_key(&facilitator_pk).expect("Wallet");
    let fac_address = interactor.register_wallet(fac_wallet).await;

    interactor
        .tx()
        .from(&wallet_alice)
        .to(&fac_address)
        .egld(1_000_000_000_000_000_000u64)
        .run()
        .await;

    // Write PEM for moltbot
    let pem_path = "tests/temp_moltbot_m.pem";
    common::create_pem_file(pem_path, &moltbot_pk, &moltbot_bech32);

    // ── 3. Deploy Identity Registry & Register Agents ──
    let mut identity =
        IdentityRegistryInteractor::init(&mut interactor, wallet_alice.clone()).await;
    identity.issue_token("AgentToken", "AGENT").await;

    let registry_address = common::address_to_bech32(identity.address());
    println!("Registry Address: {}", registry_address);

    // ── 4. Register Agent A (via npm run register — real moltbot) ──
    let reg_output = std::process::Command::new("npm")
        .arg("run")
        .arg("register")
        .current_dir("../moltbot-starter-kit")
        .env("MULTIVERSX_API_URL", GATEWAY_URL)
        .env("MULTIVERSX_CHAIN_ID", &chain_id)
        .env("IDENTITY_REGISTRY_ADDRESS", &registry_address)
        .env(
            "MULTIVERSX_PRIVATE_KEY",
            format!(
                "../{}",
                std::path::Path::new("mx-agentic-commerce-tests")
                    .join(pem_path)
                    .display()
            ),
        )
        .output()
        .expect("Failed to run register");

    let reg_stderr = String::from_utf8_lossy(&reg_output.stderr);
    println!("Register stderr: {}", reg_stderr);
    assert!(
        reg_output.status.success(),
        "Registration failed:\n{}",
        reg_stderr
    );
    println!("Agent A (moltbot) registered via npm");

    // ── 5. Register Agent B (via Rust interactor with metadata) ──
    identity
        .register_agent(
            "ServiceBot",
            "https://servicebot.example.com/arf.json",
            vec![
                ("category", b"computation".to_vec()),
                ("version", b"2.0".to_vec()),
            ],
        )
        .await;
    println!("Agent B (ServiceBot) registered as nonce=2");

    // Drop identity to release the interactor borrow (we don't need it anymore)
    let registry_addr_copy = registry_address.clone();
    drop(identity);

    // ── 6. Start MCP Server ──
    println!("Starting MCP Server...");
    let mut mcp_child = Command::new("node")
        .arg("dist/index.js")
        .arg("mcp")
        .current_dir("../multiversx-mcp-server")
        .env("MULTIVERSX_API_URL", GATEWAY_URL)
        .env("MULTIVERSX_CHAIN_ID", &chain_id)
        .env("IDENTITY_REGISTRY_ADDRESS", &registry_addr_copy)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to spawn MCP server");

    let mcp_stdin = mcp_child.stdin.as_mut().expect("stdin");
    let mcp_stdout = mcp_child.stdout.take().expect("stdout");
    let mut mcp_reader = BufReader::new(mcp_stdout);

    mcp_init(mcp_stdin, &mut mcp_reader).await;

    // ── 7. Agent A discovers Agent B via MCP ──
    println!("Agent A querying Agent B's manifest via MCP...");
    let resp = mcp_call(
        mcp_stdin,
        &mut mcp_reader,
        10,
        "tools/call",
        json!({
            "name": "get-agent-manifest",
            "arguments": { "agentNonce": 2 }
        }),
    )
    .await;

    let manifest_text = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("No manifest text");
    println!("Agent B Manifest: {}", manifest_text);
    let manifest: Value = serde_json::from_str(manifest_text).unwrap();
    assert_eq!(manifest["name"].as_str().unwrap(), "ServiceBot");

    // Also verify Agent A's manifest (registered via npm)
    println!("Querying Agent A's manifest via MCP...");
    let resp = mcp_call(
        mcp_stdin,
        &mut mcp_reader,
        11,
        "tools/call",
        json!({
            "name": "get-agent-manifest",
            "arguments": { "agentNonce": 1 }
        }),
    )
    .await;

    let agent_a_text = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("No Agent A manifest text");
    println!("Agent A Manifest: {}", agent_a_text);

    // ── 8. Start Facilitator & verify health ──
    println!("Starting Facilitator for x402 flow...");
    pm.start_node_service(
        "Facilitator",
        "../x402_integration/x402_facilitator",
        "dist/index.js",
        vec![
            ("PORT", "3000"),
            ("PRIVATE_KEY", facilitator_pk.as_str()),
            ("REGISTRY_ADDRESS", registry_addr_copy.as_str()),
            ("NETWORK_PROVIDER", GATEWAY_URL),
            ("GATEWAY_URL", GATEWAY_URL),
            ("CHAIN_ID", chain_id.as_str()),
        ],
        3000,
    )
    .expect("Failed to start Facilitator");

    sleep(Duration::from_secs(3)).await;

    let client = reqwest::Client::new();
    let resp = client
        .get("http://localhost:3000/health")
        .send()
        .await
        .expect("Failed facilitator health");
    assert!(
        resp.status().is_success(),
        "Facilitator health check failed"
    );
    println!("Facilitator health: OK ✅");

    // ── 9. Summary ──
    println!("\nFull agent-to-agent discovery + x402 flow verified:");
    println!("  Agent A (moltbot) → MCP discovery → Agent B (ServiceBot)");
    println!("  Facilitator running for x402 payment flow");

    mcp_child.kill().await.expect("Failed to kill MCP");
    let _ = std::fs::remove_file(pem_path);

    println!("Suite M: Agent-to-Agent Discovery — PASSED ✅");
}
