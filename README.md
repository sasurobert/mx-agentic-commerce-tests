# Agentic Commerce End-to-End Tests

This repository contains the full automated test suite for the MultiversX Agentic Commerce integrations (`mppx`, `mcp-payment-middleware`, `moltbot-mpp-skill`).

It utilizes `vitest` coupled with `@modelcontextprotocol/sdk/inMemory.js` to simulate instantaneous Client-Server handshakes via MCP, while actually interacting with the MultiversX network for transaction proofs.

## Running Tests
```bash
npm install
npm run test
```

## Structure
- Uses a local Devnet proxy by default.
- Attempts to load testing keys from config or automatically provisions a fresh generated EOA.
- Validates the 402 MCP Error `mpp://` protocol challenge injection.
- Triggers the MoltBot skill payment interception.

## License
MIT
