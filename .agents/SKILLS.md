# Agent Skills Index

Reusable skill runbooks for this repository. Skills live in `.agents/skills/<name>/SKILL.md`
following the Agent Skills specification (frontmatter with `name` + `description`, body under 250 lines).

## Available Skills

| Skill | Path | Description |
|-------|------|-------------|
| `private-data` | [skills/private-data/SKILL.md](skills/private-data/SKILL.md) | Sanitize sensitive coding context locally before sending it to an external model or tool, then restore placeholders only after the response returns. |
| `plugin-development` | [skills/plugin-development/SKILL.md](skills/plugin-development/SKILL.md) | Implement a new detector, policy, transformer, or vault plugin behind `plugin-api` traits. |
| `harness` | [skills/harness/SKILL.md](skills/harness/SKILL.md) | Harness engineering guide — sensor map, response protocol, and self-correction. |

## Notes

- `private-data` is the product's agent interface: it is also the file coding clients install into their own skills directory (see `README.md`).
- `plugin-development` is the contributor workflow for extending detection, policy, transformation, or storage. It encodes the hard rules from `AGENTS.md`.
- `harness` is the quality loop: local sensors (`do-harness.toml`), CI sensors, and fix procedures. Consult it when any check fires.
- Deliberately no other skills: MCP server setup is documented in `docs/client-integration.md`, and review rules live in `AGENTS.md`. Add a new skill only when a repeated workflow needs a runbook that docs alone do not cover.
