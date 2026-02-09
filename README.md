# Agentic Commerce Tests

Comprehensive integration test suite for the **MultiversX Agentic Commerce** ecosystem. Orchestrates real instances of all components — no mocks.

## Quick Start

```bash
# One-command setup (installs/builds all dependencies)
chmod +x setup.sh && ./setup.sh

# Run all tests
cargo test -- --nocapture

# Run a specific suite
cargo test --test suite_l_mcp_agent_discovery -- --nocapture
```

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| **Rust** | stable | Test runner, contract interactor |
| **Node.js** | v18+ | MCP server, relayer, facilitator, moltbot |
| **Go** | 1.20+ | Chain Simulator compilation |
| **sc-meta** | latest | WASM contract builds (optional if artifacts exist) |

The `setup.sh` script handles building all dependencies automatically.

## Architecture

The test suite follows an "Orchestrator" pattern — a Rust test runner controls:

1. **Chain Simulator** (`mx-chain-simulator-go`) — local blockchain
2. **Smart Contracts** (`mx-8004`) — Identity, Validation, Reputation registries
3. **MCP Server** (`multiversx-mcp-server`) — AI agent discovery & tools
4. **Facilitator** (`x402_facilitator`) — payment gateway
5. **Relayer** (`multiversx-openclaw-relayer`) — meta-transactions
6. **Moltbot** (`moltbot-starter-kit`) — autonomous AI agent

```
TestRunner (Rust) ──┬── Chain Simulator (port 8085)
                    ├── MCP Server (stdio / port 3001)
                    ├── Facilitator (port 3000)
                    ├── Relayer (port 3003)
                    └── Moltbot (npm scripts)
```

## Test Suites

| Suite | File | Description |
|-------|------|-------------|
| **A** | `suite_a_identity.rs` | Identity registry: deploy, issue token, register agents, verify on-chain state |
| **D** | `suite_d_facilitator.rs` | x402 facilitator: deploy, start service, health check |
| **E** | `suite_e_moltbot_lifecycle.rs` | Full moltbot lifecycle: register → update → verify |
| **E2** | `suite_e2_moltbot_update.rs` | Moltbot update-manifest flow |
| **F** | `suite_f_multi_agent.rs` | Multi-agent payment delegation |
| **G** | `suite_g_mcp_features.rs` | MCP server: init, tools/list, get-balance |
| **H** | `suite_h_relayed_registration.rs` | Relayed (meta-tx) agent registration |
| **I** | `suite_i_relayed_agent_ops.rs` | Relayed agent operations |
| **J** | `suite_j_relayed_facilitator_settle.rs` | Relayed facilitator settlement |
| **K** | `suite_k_relayed_moltbot_lifecycle.rs` | Full relayed moltbot lifecycle |
| **L** | `suite_l_mcp_agent_discovery.rs` | MCP agent discovery: register agents, query via `get-agent-manifest` |
| **M** | `suite_m_agent_to_agent_flow.rs` | Agent-to-agent: moltbot registers, discovers another agent via MCP, x402 facilitator |
| **N** | `suite_n_reputation_validation.rs` | 3-registry loop: init_job → submit_proof → verify → feedback → reputation score |
| **O** | `suite_o_mcp_tool_coverage.rs` | Comprehensive MCP tool coverage: 24 tools verified |

## Environment Variables

The test suite sets these internally — no manual configuration needed:

| Variable | Value | Source |
|----------|-------|--------|
| `MULTIVERSX_API_URL` | `http://localhost:8085` | Hardcoded in `common/mod.rs` |
| `MULTIVERSX_CHAIN_ID` | Dynamic | Queried from simulator at runtime |
| `IDENTITY_REGISTRY_ADDRESS` | Dynamic | Deployed during each test |

## Project Structure

```
mx-agentic-commerce-tests/
├── setup.sh                 # Bootstrap script
├── src/
│   ├── lib.rs              # ProcessManager export
│   └── process_manager.rs  # Chain Sim / Node service lifecycle
├── tests/
│   ├── common/mod.rs       # Shared helpers, interactors, constants
│   ├── suite_a_*.rs        # ... through suite_o_*.rs
│   └── ...
├── artifacts/              # WASM binaries (built by setup.sh)
│   ├── identity-registry.wasm
│   ├── validation-registry.wasm
│   └── reputation-registry.wasm
└── config/                 # Chain Simulator config
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `mx-chain-simulator-go` not found | Run `setup.sh` or install Go and build from `../mx-chain-simulator-go` |
| Port 8085 already in use | Kill existing simulator: `lsof -ti:8085 \| xargs kill` |
| WASM file not found | Run `cd ../mx-8004 && sc-meta all build` or `./setup.sh` |
| MCP server won't start | Run `cd ../multiversx-mcp-server && npm install && npm run build` |
| Test timeout | Increase `sleep` durations or check that simulator is responding |
