# Decouple hosted-MCP approval resume-visibility from overlay-driven `surface_version`

Status: **version-hash half LANDED** (invoke-path slice,
`feat/per-user-mcp-broker`, review handoff `2026-07-13T15-39-52-review.md`
item 3). `surface_version` (`crates/ironclaw_host_runtime/src/surface.rs`)
now excludes overlay-sourced entries from the content hash entirely, so the
"approved call silently dropped because the overlay-discovered SET or
`access` changed" failure below no longer happens. **Residual accepted as
fail-safe, open follow-up:** resume still re-runs LIVE discovery at two
layers (`capability_is_visible`'s presence check AND
`ironclaw_host_runtime::production::resolve_invocation_registry`'s
per-request registry merge), so a discovery backend that is transiently
DOWN at the moment of resume (discovery fails to return the tool at all,
not merely a different toolset) still drops the approved call. See
"Residual" below for why this was accepted rather than fixed in-slice, and
the per-user-store target architecture where the full fix belongs.

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

## Consequence (as originally found — now narrowed by the landed fix)

Raise an approval gate for a hosted-MCP tool on turn N (overlay UP, version
V1). The user approves later — human approvals routinely land minutes/hours
after the raising turn. If discovery is transiently down, or returns a
different toolset, at approval time, the rebuilt surface is V2 ≠ V1, so the
**approved call is silently dropped** as no-longer-visible.

This is the safe failure direction (never runs an invisible tool) but is a
real functionality regression, not just cache churn — an approval a user
explicitly granted quietly does nothing.

## Fix direction — DONE (version-hash half)

Decoupled the resume-visibility check from the overlay-driven content-hash
version: `surface_version` (`crates/ironclaw_host_runtime/src/surface.rs`)
now excludes overlay-sourced entries from the hash entirely (not merely
reduced to their id — their SET is exactly the discovery-health-dependent
state that must not flip the version). The per-id presence check in
`capability_is_visible`
(`crates/ironclaw_agent_loop/src/executor/capability_helpers.rs:210-223`)
remains the real "is this specific tool still there" authority, so a
genuinely revoked/removed discovered capability still fails closed —
verified by
`surface_version_is_stable_across_an_overlay_discovery_health_flip`
(`ironclaw_host_runtime::surface::tests`).

## Residual — accepted as fail-safe, tracked here as the open half

Resume re-runs LIVE discovery at two independent layers even after the
version-hash fix: `capability_is_visible`'s presence check (rebuilt from a
fresh `visible_capabilities` call) and
`ironclaw_host_runtime::production::resolve_invocation_registry` (the
per-request registry merge resume threads through preflight, added by the
same invoke-path slice). If the discovery backend is transiently DOWN at
the exact moment of resume — not a different toolset, but discovery
failing to return the tool at all — both layers independently see nothing
and the approved call drops. This fails CLOSED (never mis-invokes) and is
bounded by the overlay's TTL/budget window, but is not proven to survive a
resume landing mid-outage.

**Why not fixed in this slice:** the real fix (cache the discovered
descriptor at gate-raise time, honor it at resume regardless of live
discovery state) requires a per-user discovery STORE, not a read-time
overlay call — that crosses into the deferred per-user-store target
architecture (the architectural audit's F1/F2/F3 end-state: a scheduled
discovery service writing a per-user, dispatch-visible store that both the
surface and dispatch read passively) and introduces its own revocation-
window question (a cached descriptor would rely entirely on the
marketplace `/mcp` broker's own re-check at dispatch time). That is a
materially larger change than this slice's scope.

## Scope

Touches `ironclaw_agent_loop` (the executor gate, version-hash decoupling —
DONE) and `ironclaw_host_runtime` (`surface_version` composition — DONE).
The residual (discovery-down-at-resume survival) requires the per-user
discovery store described above and stays an open, unscheduled follow-up.
