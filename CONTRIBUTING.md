# Contributing to arkforge-mcp

## Before you start

Open an issue first for any non-trivial change. This avoids wasted effort if the direction doesn't fit the project.

For typos and small doc fixes, a PR directly is fine.

## Branching

- `main` is stable and protected — no direct push
- Create a branch from `main`: `feat/your-feature` or `fix/your-fix`
- Open a PR against `main`

## Development setup

```bash
git clone https://github.com/ark-forge/arkforge-mcp.git
cd arkforge-mcp
pip install -e ".[dev]"
```

Set your API key:

```bash
export ARKFORGE_API_KEY=your_key_here
```

Get a free key at [arkforge.tech](https://arkforge.tech).

## Running the server locally

```bash
python -m arkforge_mcp.server
```

Or via MCP CLI:

```bash
mcp run src/arkforge_mcp/server.py
```

## Pull request checklist

- [ ] Tested manually against the live API
- [ ] README updated if behavior changed
- [ ] CHANGELOG entry added under `[Unreleased]`
- [ ] Version bumped in `pyproject.toml` if this is a release

## What we accept

- Bug fixes
- New MCP tools that extend the Trust Layer API surface
- Improved error messages
- Documentation improvements

## What we don't accept

- New dependencies without discussion
- Changes to the proof format or verification logic without opening an issue first
- Breaking changes to existing tool signatures

## Questions

Open an issue or reach out at [arkforge.tech](https://arkforge.tech).
