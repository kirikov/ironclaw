# Decouple hosted-MCP approval resume-visibility from overlay-driven `surface_version`

Status: open follow-up, not yet scheduled.

## Context

Found during review of the per-user hosted-MCP broker overlay
(`feat/per-user-mcp-broker`, developer handoff `2026-07-13T09-01-40`,
reviewer handoff `2026-07-13T09-27-09`, impl-critic finding F2).

`surface_version` folds the actual rendered capability list
(`crates/ironclaw_host_runtime/src/surface.rs`), so for a fixed scope it now
legitimately flips floor-only ⇄ floor+overlay with hosted-MCP
marketplace/discovery health. Every discovered hosted-MCP tool defaults to
`PermissionMode::Ask` (`crates/ironclaw_extensions/src/hosted_mcp_discovery.rs`),
so approval-gating is the *primary* path for these tools, not a corner case.

`capability_is_visible`
(`crates/ironclaw_agent_loop/src/executor/capability_helpers.rs`) returns
`false` when `call.surface_version != surface.version`, and approval/auth
resume candidates carry the surface version captured when the gate was
raised.

## Consequence

Raise an approval gate for a hosted-MCP tool on turn N (overlay UP, version
V1). The user approves later — human approvals routinely land minutes/hours
after the raising turn. If discovery is transiently down, or returns a
different toolset, at approval time, the rebuilt surface is V2 ≠ V1, so the
**approved call is silently dropped** as no-longer-visible.

This is the safe failure direction (never runs an invisible tool) but is a
real functionality regression, not just cache churn — an approval a user
explicitly granted quietly does nothing.

## Fix direction

Decouple the resume-visibility check from the overlay-driven content-hash
version — e.g. match on the capability id, or a scope+policy-stable version
component, for resume gating, rather than the full content hash that now
moves with hosted-MCP discovery health.

## Scope

Touches `ironclaw_agent_loop` (the executor gate) and possibly
`ironclaw_host_runtime` (surface_version composition) — a different
subsystem/crate than the overlay PR that surfaced this, so intentionally
deferred as a fast-follow rather than bundled into that PR (per
`.claude/rules/review-discipline.md` PR Scope Discipline).
