# Agentic Commerce Tests

This repository contains the comprehensive integration and end-to-end test suite for the **MultiversX Agentic Commerce** ecosystem. It orchestrates real instances of all components to verify complex multi-agent interactions, payments, and blockchain state changes without relying on mocks.

## 🏗 Architecture

The test suite follows an "Orchestrator" pattern, managed by a Rust-based test runner that controls the lifecycle of:

1.  **Chain Simulator**: `mx-chain-simulator-go` (Local blockchain network)
2.  **Smart Contracts**: `mx-8004` (Identity & Service Registry)
3.  **MCP Server**: `multiversx-mcp-server` (Model Context Protocol for AI Agents)
4.  **Facilitator**: `x402-facilitator` (Payment Gateway & Verifier)
5.  **AI Agents**: `moltbot-starter-kit` (Autonomous agents paying for services)

## 🧪 Test Suites

The project is divided into several test suites, each focusing on specific aspects of the ecosystem:

| Suite | Description | Focus |
| :--- | :--- | :--- |
| **Suite A: Identity** | `suite_a_identity.rs` | Verifies agent registration, identity proofs, and on-chain registry updates. |
| **Suite D: Facilitator** | `suite_d_facilitator.rs` | Tests the 402 Payment Required flow, payment verification, and settlement. |
| **Suite E: Moltbot Lifecycle** | `suite_e_moltbot_lifecycle.rs` | End-to-end journey of an agent: startup, registration, discovery, and getting paid. |
| **Suite F: Multi-Agent** | `suite_f_multi_agent.rs` | Complex scenarios where agents hire other agents, delegating tasks and payments. |
| **Suite G: MCP Features** | `suite_g_mcp_features.rs` | Comprehensive coverage of all MCP tools (Balance and Transaction queries, Token issuance, etc.). |
| **Suite H: Relayed Registration** | `suite_h_relayed_registration.rs` | Tests meta-transactions and relayed interactions for gas-less agent onboarding. |

## 🚀 Getting Started

### Prerequisites

- **Rust**: Latest stable version
- **Node.js**: v18+
- **Go**: v1.20+ (for Chain Simulator)
- **Docker** (Optional, if running simulator via container)

### Running Tests

To run the full suite of tests:

```bash
cargo test
```

To run a specific suite:

```bash
cargo test --test suite_e_moltbot_lifecycle
```

## 📂 Project Structure

- `tests/`: Rust integration tests.
- `src/`: Helper modules and test infrastructure.
- `config/`: Configuration files for the Chain Simulator and other services.
- `mx-chain-simulator-go/`: Submodule or local copy of the blockchain simulator.

## 🤝 Contributing

Contributions are welcome! Please ensure that any new features include corresponding tests in the appropriate suite.

## 📄 License

MIT License
