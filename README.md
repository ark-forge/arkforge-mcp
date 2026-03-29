# ArkForge Trust Layer — MCP Server

Third-party certifying proxy — get an independent cryptographic proof for any HTTP call.

Works with **AI agents, webhooks, microservices, or any HTTP client**.
The proof is signed by ArkForge (independent third party) — **not by the caller**.

<a href="https://glama.ai/mcp/servers/ark-forge/arkforge-mcp">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/ark-forge/arkforge-mcp/badge" alt="ArkForge Trust Layer MCP server" />
</a>

---

## Why this matters

When a system makes an HTTP call, there is no independent record of what was sent, what was received, or when it happened. Either party could deny or alter the transaction.

ArkForge fixes this by acting as a **certifying proxy**: the caller routes its request through ArkForge, which signs the full request+response bundle with an Ed25519 key, timestamps it via RFC 3161, and anchors it in [Sigstore Rekor](https://rekor.sigstore.dev) — an immutable, publicly auditable log.

The resulting proof is permanently verifiable at a public URL, by anyone, without contacting ArkForge.

**This is the difference between a self-signed certificate and a CA-issued one.** Other tools produce proofs signed by the caller itself. ArkForge produces proofs signed by an independent third party.

---

## Use cases

- **AI agents** — audit trail for every external API call (Claude, GPT, Mistral, LangChain, AutoGen)
- **Webhooks** — prove a Stripe or GitHub event was received with this exact payload
- **Microservices** — tamper-evident log between internal services (compliance, fintech)
- **Data providers** — prove an external API returned this value at this timestamp
- **Automations** — certify an action in an n8n or Zapier workflow

---

## Installation

```json
{
  "mcpServers": {
    "arkforge": {
      "command": "uvx",
      "args": ["arkforge-mcp"],
      "env": {
        "ARKFORGE_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

Get a free API key (500 proofs/month) at [arkforge.tech](https://arkforge.tech).

---

## Tools

### `certify_call`
Route an HTTP call through ArkForge and get a cryptographic proof of the transaction.

```
target          URL of the upstream API to call
payload         JSON body (optional)
method          "POST" or "GET" (default: "POST")
description     Human-readable description included in the proof
agent_identity  Identifier for the calling system (optional)
```

Returns `proof_id`, `verification_url`, `upstream_response`, `chain_hash`, `timestamp`, and Ed25519 `signature`.

**Use this instead of calling the API directly** when you need an auditable record.

Example response:

```json
{
  "proof_id": "prf_20260310_143022_a1b2c3",
  "verification_url": "https://trust.arkforge.tech/v1/proof/prf_20260310_143022_a1b2c3",
  "upstream_response": { "status": "ok" },
  "chain_hash": "e3b0c44298fc1c149afb...",
  "timestamp": "2026-03-10T14:30:22.481Z",
  "timestamp_authority": "verified",
  "rekor_log_id": "https://rekor.sigstore.dev/api/v1/log/entries/...",
  "seller": "api.example.com",
  "signature": "MCowBQYDK2VwAyEA..."
}
```

### `get_proof`
Retrieve the full proof bundle for a given `proof_id`.

### `verify_proof`
Get a human-readable summary of what a proof certifies — useful for explaining to a user or auditor what was independently verified.

### `get_usage`
Check your remaining credits for the current month.

---

## What each proof contains

| Field | Description |
|---|---|
| `proof_id` | Unique identifier — permanent public URL |
| `hashes.request` | SHA-256 of the exact request sent |
| `hashes.response` | SHA-256 of the exact response received |
| `hashes.chain` | Combined hash — tamper-evident |
| `parties.seller` | Domain of the called API |
| `timestamp_authority` | RFC 3161 timestamp via FreeTSA (QTSP eIDAS on Enterprise) |
| `rekor` | Sigstore Rekor immutable log entry |
| `arkforge_signature` | Ed25519 signature by ArkForge's independent key |

---

## Pricing

| Plan | Proofs/month | Price |
|---|---|---|
| Free | 500 | €0 |
| Pro | 5,000 | €29/month |
| Enterprise | 50,000 + QTSP eIDAS | €149/month |

[Get your API key →](https://arkforge.tech)

---

## REST API

The MCP server is one integration path. The same API works from any language or framework:

```bash
curl -X POST https://trust.arkforge.tech/v1/proxy \
  -H "X-Api-Key: your_key" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://api.example.com/action", "payload": {"data": "value"}}'
```