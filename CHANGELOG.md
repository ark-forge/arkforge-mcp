# Changelog

All notable changes to this project will be documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [Unreleased]

---

## [1.0.0] — 2026-03-10

### Added
- `certify_call` — route any HTTP call through ArkForge and get a cryptographic proof
- `get_proof` — retrieve a full proof bundle by ID
- `verify_proof` — human-readable summary of what a proof certifies
- `get_usage` — check remaining credits for the current month
- Ed25519 signature of the full request+response bundle
- RFC 3161 timestamp via FreeTSA
- Sigstore Rekor immutable log anchor
- Smithery registry support (`smithery.yaml`, `.well-known/mcp/server-card.json`)
- Glama registry support (`glama.json`)
- Free tier: 500 proofs/month

[Unreleased]: https://github.com/ark-forge/arkforge-mcp/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/ark-forge/arkforge-mcp/releases/tag/v1.0.0
