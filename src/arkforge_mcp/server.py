#!/usr/bin/env python3
"""
ArkForge Trust Layer — MCP Server
Third-party cryptographic proof for AI agent API calls.

Works with Claude, GPT-4, Mistral, LangChain, AutoGen, or any HTTP client.
The proof is signed by ArkForge (independent third party) — not by your agent.

Each certified call produces:
- Ed25519 signature of the full request+response bundle
- RFC 3161 timestamp (FreeTSA or QTSP eIDAS)
- Sigstore Rekor immutable log entry
- archive.org snapshot
- Publicly verifiable at trust.arkforge.tech/v1/proof/{proof_id}

Get a free API key at arkforge.tech.
"""

import os
import json
import httpx
from mcp.server.fastmcp import FastMCP

BASE_URL = os.environ.get("ARKFORGE_BASE_URL", "https://trust.arkforge.tech").rstrip("/")
TIMEOUT = 30.0

mcp = FastMCP(
    "ArkForge Trust Layer",
    instructions=(
        "Use certify_call instead of calling external APIs directly when you need "
        "a cryptographic proof of what happened. The response from the upstream API "
        "is returned alongside the proof, so your workflow is not interrupted. "
        "Use get_proof to inspect an existing proof. Use verify_proof to get a "
        "human-readable summary of what a proof certifies. Use get_usage to check "
        "remaining credits. Use assess_mcp_server to audit an MCP server's security "
        "posture. Use compliance_report to generate an EU AI Act or ISO 42001 report."
    ),
    json_response=True,
)


def _headers() -> dict:
    return {
        "X-Api-Key": os.environ.get("ARKFORGE_API_KEY", ""),
        "Content-Type": "application/json",
        "User-Agent": "arkforge-mcp/1.2.2",
    }


def _format_error(r: httpx.Response) -> str:
    try:
        body = r.json()
        err = body.get("error", {})
        return f"Error {r.status_code}: {err.get('message', r.text[:200])}"
    except Exception:
        return f"Error {r.status_code}: {r.text[:200]}"


def _require_key() -> str | None:
    if not os.environ.get("ARKFORGE_API_KEY"):
        return "Error: ARKFORGE_API_KEY environment variable not set. Get a free key at arkforge.tech."
    return None


@mcp.tool()
def certify_call(
    target: str,
    payload: dict = None,
    method: str = "POST",
    description: str = "",
    agent_identity: str = "",
) -> str:
    """
    Call an external API and get a cryptographic proof of the transaction.

    Use this INSTEAD of calling the API directly when you need an auditable,
    tamper-evident record of what was sent and received.

    The proof is signed by ArkForge (independent third party), timestamped
    via RFC 3161, and anchored in Sigstore Rekor — not self-signed by your agent.

    Args:
        target: URL of the upstream API to call (e.g. "https://api.example.com/v1/action")
        payload: JSON body to send to the upstream API (optional for GET requests)
        method: HTTP method — "POST" or "GET" (default: "POST")
        description: Human-readable description of what this call does (included in the proof)
        agent_identity: Identifier for the calling agent (optional, included in the proof)

    Returns:
        JSON with proof_id, verification_url, the upstream API response, chain_hash,
        and timestamp. Share verification_url with any third party to let them
        independently verify what happened.
    """
    if err := _require_key():
        return err
    if not target:
        return "Error: 'target' is required — provide the URL of the upstream API to call."

    body: dict = {"target": target, "method": method.upper()}
    if payload:
        body["payload"] = payload
    if description:
        body["description"] = description
    if agent_identity:
        body["extra_headers"] = {"X-Agent-Identity": agent_identity}

    try:
        with httpx.Client(timeout=TIMEOUT) as client:
            r = client.post(f"{BASE_URL}/v1/proxy", headers=_headers(), json=body)

        if r.status_code != 200:
            return _format_error(r)

        data = r.json()
        proof = data.get("proof", {})
        tlog = proof.get("transparency_log", {})

        result = {
            "proof_id": proof.get("proof_id"),
            "verification_url": proof.get("verification_url"),
            "upstream_response": data.get("service_response"),
            "chain_hash": proof.get("hashes", {}).get("chain"),
            "timestamp": proof.get("timestamp"),
            "timestamp_authority": proof.get("timestamp_authority", {}).get("status"),
            "rekor_status": tlog.get("status"),
            "rekor_verify_url": tlog.get("verify_url"),
            "seller": proof.get("parties", {}).get("seller"),
            "signature": proof.get("arkforge_signature"),
        }

        return json.dumps(result, indent=2, ensure_ascii=False)

    except httpx.TimeoutException:
        return f"Error: Request timed out after {TIMEOUT}s. The upstream API may be slow."
    except Exception as e:
        return f"Error: {e}"


def _fetch_proof(proof_id: str):
    """Fetch proof bundle from API. Returns (dict, None) on success or (None, error_str)."""
    try:
        with httpx.Client(timeout=TIMEOUT) as client:
            r = client.get(f"{BASE_URL}/v1/proof/{proof_id}", headers=_headers())
        if r.status_code == 404:
            return None, f"Proof '{proof_id}' not found."
        if r.status_code != 200:
            return None, _format_error(r)
        return r.json(), None
    except httpx.TimeoutException:
        return None, "Error: Request timed out."
    except Exception as e:
        return None, f"Error: {e}"


@mcp.tool()
def get_proof(proof_id: str) -> str:
    """
    Retrieve the full cryptographic proof for a given proof ID.

    Returns the complete proof bundle: request/response hashes, parties,
    RFC 3161 timestamp, Sigstore Rekor log entry, and archive.org snapshot.

    Args:
        proof_id: The proof identifier (e.g. "prf_20260310_143022_a1b2c3")
    """
    if not proof_id:
        return "Error: 'proof_id' is required."
    data, err = _fetch_proof(proof_id)
    if err:
        return err
    return json.dumps(data, indent=2, ensure_ascii=False)


@mcp.tool()
def verify_proof(proof_id: str) -> str:
    """
    Get a human-readable summary of what a proof certifies.

    Useful for explaining to a user or auditor what was independently
    verified, without reading raw JSON.

    Args:
        proof_id: The proof identifier (e.g. "prf_20260310_143022_a1b2c3")
    """
    if not proof_id:
        return "Error: 'proof_id' is required."

    p, err = _fetch_proof(proof_id)
    if err:
        return err

    hashes = p.get("hashes", {})
    parties = p.get("parties", {})
    tsa = p.get("timestamp_authority", {})
    tlog = p.get("transparency_log", {})
    archive = p.get("archive_org", {})

    lines = [
        f"Proof ID: {p.get('proof_id')}",
        f"Timestamp: {p.get('timestamp')} (UTC)",
        f"",
        f"What was certified:",
        f"  - Caller fingerprint: {parties.get('buyer_fingerprint', 'N/A')[:16]}...",
        f"  - Called API (seller): {parties.get('seller', 'N/A')}",
    ]
    if parties.get("agent_identity"):
        lines.append(f"  - Agent identity: {parties['agent_identity']}")

    lines += [
        f"",
        f"Integrity:",
        f"  - Request hash:  {hashes.get('request', 'N/A')}",
        f"  - Response hash: {hashes.get('response', 'N/A')}",
        f"  - Chain hash:    {hashes.get('chain', 'N/A')}",
        f"",
        f"Independent anchoring:",
    ]

    tsa_provider = tsa.get("provider", "N/A")
    lines.append(f"  - RFC 3161 timestamp ({tsa_provider}): {tsa.get('status', 'unknown')}")

    if tlog.get("status") == "verified":
        lines.append(f"  - Sigstore Rekor: verified (logIndex={tlog.get('log_index')})")
        if tlog.get("verify_url"):
            lines.append(f"    {tlog['verify_url']}")
    else:
        lines.append(f"  - Sigstore Rekor: {tlog.get('status', 'pending')}")

    if archive.get("snapshot_url"):
        lines.append(f"  - archive.org snapshot: {archive['snapshot_url']}")

    verification_url = p.get("verification_url") or f"{BASE_URL}/v1/proof/{p.get('proof_id')}"
    lines += [
        f"",
        f"Public verification URL:",
        f"  {verification_url}",
    ]

    return "\n".join(lines)


@mcp.tool()
def get_usage() -> str:
    """
    Check your ArkForge API usage and remaining credits for the current period.

    Returns your tier (Free / Pro / Enterprise), proofs used, proofs remaining,
    and the reset date.
    """
    if err := _require_key():
        return err

    try:
        with httpx.Client(timeout=TIMEOUT) as client:
            r = client.get(f"{BASE_URL}/v1/usage", headers=_headers())

        if r.status_code != 200:
            return _format_error(r)

        data = r.json()
        monthly = data.get("monthly", {})
        lines = [
            f"Plan: {data.get('plan', 'N/A').capitalize()}",
            f"Proofs used this month: {monthly.get('used', 'N/A')} / {monthly.get('limit', 'N/A')}",
            f"Proofs remaining: {monthly.get('remaining', 'N/A')}",
        ]
        if data.get("plan") == "free":
            lines.append("Upgrade to Pro (5000 proofs/month): https://arkforge.tech/#pricing")

        return "\n".join(lines)

    except httpx.TimeoutException:
        return "Error: Request timed out."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def assess_mcp_server(
    server_id: str,
    tools: list,
    server_version: str = "",
) -> str:
    """
    Assess an MCP server's security posture and get a certified proof of the assessment.

    Analyzes the server's tool manifest for dangerous capability patterns
    (filesystem write, code execution, env access, network), detects drift
    from the previous baseline, and tracks version changes.

    Args:
        server_id:      Stable identifier for the MCP server (e.g. "my-mcp-server").
        tools:          List of tool dicts with at minimum a "name" field.
                        Optional: "description", "inputSchema", "version".
        server_version: Optional server version string (e.g. "1.2.0").

    Returns:
        JSON with assess_id, risk_score (0-100), findings (severity, tool, message),
        drift_detected, baseline_status, and assessed_at.
    """
    if err := _require_key():
        return err
    if not server_id:
        return "Error: 'server_id' is required."
    if not isinstance(tools, list):
        return "Error: 'tools' must be a list of tool dicts."

    body: dict = {"server_id": server_id, "manifest": {"tools": tools}}
    if server_version:
        body["server_version"] = server_version

    try:
        with httpx.Client(timeout=TIMEOUT) as client:
            r = client.post(f"{BASE_URL}/v1/assess", headers=_headers(), json=body)

        if r.status_code != 200:
            return _format_error(r)

        data = r.json()
        risk = data.get("risk_score", 0)
        risk_label = "HIGH" if risk >= 70 else "MEDIUM" if risk >= 40 else "LOW" if risk >= 10 else "CLEAN"
        findings = data.get("findings", [])

        result = {
            "assess_id": data.get("assess_id"),
            "server_id": data.get("server_id", server_id),
            "assessed_at": data.get("assessed_at"),
            "risk_score": risk,
            "risk_level": risk_label,
            "baseline_status": data.get("baseline_status"),
            "drift_detected": data.get("drift_detected", False),
            "drift_summary": data.get("drift_summary"),
            "findings_count": len(findings),
            "findings": findings,
        }

        return json.dumps(result, indent=2, ensure_ascii=False)

    except httpx.TimeoutException:
        return "Error: Request timed out."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def compliance_report(
    date_from: str,
    date_to: str,
    framework: str = "eu_ai_act",
) -> str:
    """
    Generate a compliance report for all proofs certified under your API key.

    Aggregates proofs in the given date range and maps them to the articles
    of the requested compliance framework.

    Args:
        date_from: ISO 8601 start date (e.g. "2026-01-01").
        date_to:   ISO 8601 end date (e.g. "2026-12-31").
        framework: Compliance framework — "eu_ai_act" (default) or "iso_42001".

    Returns:
        JSON with report_id, framework, proof_count, articles coverage,
        gaps list, and summary (covered / partial / gap / not_applicable).
    """
    if err := _require_key():
        return err
    if not date_from or not date_to:
        return "Error: 'date_from' and 'date_to' are required (ISO 8601 format)."

    try:
        with httpx.Client(timeout=60.0) as client:
            r = client.post(
                f"{BASE_URL}/v1/compliance-report",
                headers=_headers(),
                json={"framework": framework, "date_from": date_from, "date_to": date_to},
            )

        if r.status_code != 200:
            return _format_error(r)

        return json.dumps(r.json(), indent=2, ensure_ascii=False)

    except httpx.TimeoutException:
        return "Error: Request timed out."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_agent_reputation(agent_id: str) -> str:
    """
    Get the public reputation score for an agent (0-100).

    The score is computed from certified proof history: success rate,
    dispute ratio, identity consistency, and proof volume.

    Args:
        agent_id: Agent identifier (e.g. "my-agent-v1").

    Returns:
        JSON with reputation_score, scoring details, and total_proofs.
    """
    if not agent_id:
        return "Error: 'agent_id' is required."

    try:
        with httpx.Client(timeout=TIMEOUT) as client:
            r = client.get(f"{BASE_URL}/v1/agent/{agent_id}/reputation", headers=_headers())

        if r.status_code != 200:
            return _format_error(r)

        return json.dumps(r.json(), indent=2, ensure_ascii=False)

    except httpx.TimeoutException:
        return "Error: Request timed out."
    except Exception as e:
        return f"Error: {e}"


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
