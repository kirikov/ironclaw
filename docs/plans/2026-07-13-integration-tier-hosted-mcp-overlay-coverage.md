# Integration-tier coverage for the per-user hosted-MCP broker overlay (N3)

Status: open follow-up, not yet scheduled.

## Context

Found during review of the per-user hosted-MCP broker overlay
(`feat/per-user-mcp-broker`, developer handoffs `2026-07-13T09-01-40` /
`2026-07-13T10-01-04` / `2026-07-13T10-12-40`, reviewer handoffs
`2026-07-13T09-27-09` / `2026-07-13T10-09-56`).

The overlay's own correctness (union/gate/dedup/budget, cache/single-flight,
multi-tenant isolation) is covered at two tiers: 9 composition-crate tests
(`crates/ironclaw_reborn_composition/src/extension_host/hosted_mcp_overlay.rs`)
and 11 host_runtime-crate tests, the latter driven through the real
`DefaultHostRuntime::visible_capabilities` (confirmed no branching sits
between that and `CapabilityCatalog::visible_capabilities`).

What is NOT covered: whether the real product-workflow → turn-coordinator →
agent-loop chain actually threads an agent-scoped `ExecutionContext` down to
`visible_capabilities` in an in-process `tests/integration/` scripted turn,
the way `crates/ironclaw_reborn_composition/src/product_live_adapters.rs::visible_capability_request_for_run`
claims. This tier is otherwise "cheap and available now" (no Postgres, no
external services — see `tests/integration/CLAUDE.md`), but two concrete
harness gaps block it today, found by tracing the actual harness code
(not by assumption):

## Blocker 1 — no HTTPS-capable mock MCP server

`is_hosted_http_mcp_package` (`crates/ironclaw_extensions/src/hosted_mcp_discovery.rs`,
`valid_hosted_mcp_url`) requires scheme `https`. `surface.rs`'s
`discover_overlay_capabilities` filters registry packages through this
predicate BEFORE ever calling the overlay (real or fake) — a package that
doesn't satisfy it is invisible to the overlay mechanism entirely.

The integration harness's only MCP test double
(`tests/integration/support/harness_mcp.rs`'s `LoopbackMcpRuntimeHttpEgress`
+ `support/mock_mcp_server.rs`'s `MockMcpServer`) explicitly rejects
anything but `http://127.0.0.1` (`LoopbackMcpRuntimeHttpEgress::new`'s own
hermetic guard). There is no HTTPS-serving mock MCP server anywhere in
`tests/integration/` today.

## Blocker 2 — `local_dev_host_runtime_with_registry_egress_and_mcp` never wires the overlay

`tests/integration/support/harness_mcp.rs`'s
`local_dev_host_runtime_with_registry_egress_and_mcp` hand-builds
`HostRuntimeServices::new(...)` directly and contains zero references to
`attach_hosted_mcp_overlay` or `HostedMcpSurfaceOverlay` — it only exercises
the older static-registration hosted-MCP path
(`.with_mcp_runtime(...)`), never the broker overlay
(`.with_hosted_mcp_overlay(...)`). `CompositionHostedMcpOverlay` itself is
`pub(crate)` to `ironclaw_reborn_composition`, not visible from
`tests/integration/` (a separate crate), so this needs a new test-visible
fake `HostedMcpSurfaceOverlay` (the trait is public), not the real
composition impl.

## Secondary open question

Whether the harness's default resolved binding
(`ironclaw_product_workflow::ResolvedBinding.agent_id: Option<AgentId>`)
is ever populated (`Some`) by default, or needs an explicit
`default_agent_id` configured on the binding-resolution path.
`test_product_scope()` (`tests/integration/support/harness/mod.rs`) does
accept a custom `agent_id: &str` and is already used with non-default
agent ids elsewhere (`secrets.rs`, `support/group.rs`), so scope-level
agent variation is possible — but that alone does not answer whether a
turn-coordinator-resolved (not hand-built) `ResourceScope` carries one for
the harness's default test adapter/installation.

## Risk mitigated today (why this is a fast-follow, not a blocker)

The specific risk this tier would close is "does the upstream
product-workflow → turn-coordinator → agent-loop chain thread agent scope
correctly into the capability surface." That risk is partially covered
today, not uncovered:

- `crates/ironclaw_host_runtime/src/production.rs`'s
  `hosted_mcp_overlay_wiring::multi_tenant_turns_see_only_their_own_overlay_capabilities`
  drives the real `DefaultHostRuntime::visible_capabilities` with two
  independently-constructed `ExecutionContext`s differing only in
  `agent_id`, proving the merge/gate/dedup logic is agent-scope-correct at
  that layer.
- `visible_capability_request_for_run`
  (`crates/ironclaw_reborn_composition/src/product_live_adapters.rs`), the
  one function that copies `run_context.scope.agent_id` into the
  `ExecutionContext`/`ResourceScope` the overlay gate reads, is a short,
  branch-free field copy — read again during this review pass, still no
  conditional logic that could silently drop the field.
- Per team-lead: the orchestrator also has a planned live E2E path that
  will exercise a real managed-worker turn end-to-end; that is a separate,
  heavier-weight validation this integration-tier follow-up does not need
  to duplicate once it lands.

What remains genuinely uncovered is the narrower "does the real
product-workflow binding-resolution path actually produce an agent-scoped
`ResourceScope` for a hosted-MCP-capable hire, in-process, hermetically" —
this doc's scope.

## Fix direction

1. Add an HTTPS-capable variant of the mock MCP server/egress (or a
   scheme-relaxed test-only builder path that satisfies
   `is_hosted_http_mcp_package`'s intent without a real TLS handshake —
   needs a decision on which is more honest to what production actually
   validates).
2. Add `.with_hosted_mcp_overlay(fake_overlay)` wiring to
   `local_dev_host_runtime_with_registry_egress_and_mcp` (or a sibling
   constructor) plus a small test-visible fake `HostedMcpSurfaceOverlay` in
   the `tests/integration/support/` tree.
3. Confirm (or add) a way to get a real turn-coordinator-resolved binding
   with `agent_id: Some(...)` for the scripted turn.
4. Add one hosted-mcp-flavored scripted turn: a worker sees its hire's
   discovered tool in `assert_model_tools_contains`, the static floor
   (`submit`-equivalent) is still present.

## Scope

Test-infrastructure work in `tests/integration/support/`, separable from
the overlay implementation itself — the overlay's correctness is already
covered at the crate tiers listed above. Deferred as a fast-follow per
`.claude/rules/review-discipline.md` PR Scope Discipline, same as the
`surface_version` approval-resume-visibility follow-up
(`2026-07-13-decouple-hosted-mcp-approval-resume-visibility.md`).
