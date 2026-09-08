# IronClaw fork ↔ upstream sync — report

**Date:** 2026-09-08
**Fork:** `kirikov/ironclaw` · **Upstream:** `nearai/ironclaw`
**Work branch:** `sync/upstream-main-2026-09-08` in `~/Developer/ironclaw-sync` (separate worktree)
**Untouched:** `deploy/ironclaw2` (auto-deploys to production), upstream repo

## 1. What runs on this stand

`ironclaw2.service` → `~/Developer/ironclaw/target/debug/ironclaw serve --port 3010`, built from branch
`deploy/ironclaw2` (fork `kirikov/ironclaw`), profile `hosted_multi_tenant`.

A second unit, `ironclaw-reborn.service` (port 3000, `~/Developer/ironclaw-fork`), is dead: its binary
`target/dist/ironclaw-reborn` does not exist, so systemd has been restart-looping it 863k times. It is
not part of this sync; worth either fixing or disabling separately.

## 2. Sync result

Before: **17 commits ahead, 483 behind** upstream `main`.
After: **0 behind**, 18 ahead — and the fork delta is now only what is genuinely ours.

| | before | after |
|---|---|---|
| files differing from upstream | 427 | **64** |
| lines | +9 136 / −33 897 | **+3 812 / −107** |

Most of that reduction is noise removal: the fork's last deploy commit (`21cf3dc60`) had squashed an
upstream sync into the same commit as a feature, so git saw hundreds of stale copies of upstream files
as fork changes. Those are gone.

The merge was expensive because upstream reorganized the whole workspace in the meantime:

- flat `crates/*` → layered `crates/{app,contracts,domains,events,extensions,kernel,lanes,loop,product,substrates}/*`
- `ironclaw_extensions` split into `ironclaw_extension_registry` + `ironclaw_extension_contracts`
- `ironclaw_reborn_composition` → `ironclaw_composition`, `ironclaw_reborn_cli` → `ironclaw_cli`
- `ironclaw_mcp` split from one file into 7 chartered modules (`contract`/`runtime`/`client`/`jsonrpc`/`discovery`/`egress`/`diagnostics`)
- `ironclaw_host_api` flat re-exports → module paths (`ids::`, `capability::`, `action::`, `resource::`, …)

160 merge conflicts; 134 were stale-upstream noise, 26 carried real fork code and were re-ported by hand.

## 3. Our features: what happened to each

### Already fixed upstream — dropped from the fork

**Webchat 14 MiB body limit** (`d2bc6618e`).
Same bug, same root cause, fixed upstream independently. We raised axum's `DefaultBodyLimit` to
`config.max_body_bytes`; upstream calls `DefaultBodyLimit::disable()` underneath its own
`RequestBodyLimitLayer`, which is the cleaner form. Upstream's comment describes the identical failure
(the implicit 2 MiB extractor cap silently overriding the declared 14 MiB contract). **Take upstream's.**

**Skill storage split** (`96ee03d3b`, "make skill_list see installed skills").
Our fix pointed every skill mount view at the durable `/tenants` tree. Upstream went further under
`nearai/ironclaw#7168`: skill mounts are now **database-backed** (`db_backed_skill_management_mount_view`),
the same tree the reader and Settings use. Our disk-store variant would fight that design, so it is
dropped in favour of upstream's — including our `local_skill_listing` module and the owner-walking
`ironclaw skills list --tenant/--user` CLI.
⚠️ **The CLI half of the bug is still open upstream** — see PR 5 below.

### Still ours — carried onto upstream

| Feature | Upstream state | Notes |
|---|---|---|
| Per-(tenant, user, thread) discovered hosted-MCP catalogs (`ScopedPackageOverlay`) | **`nearai/ironclaw#6778` still OPEN** | The flagship fix. Upstream still publishes one catalog per extension id. |
| Merge-instead-of-replace for discovered catalogs | not upstream | Upstream's own test is still named `discovered_mcp_tools_replace_provider_capabilities_with_inline_schemas`. |
| Manifest declarations survive discovery (financial `hire_agent` keeps its effects) | not upstream | |
| Opt-in SEP-414 `_meta` caller attribution on `tools/list` / `tools/call` | not upstream | Upstream has `invocation_id` for connection keying only; nothing reaches the wire. |
| Bundled `agent-market` first-party extension | not upstream | Fork-specific product surface; least likely to be accepted as-is. |
| `InstalledLocal` (volume-installed) providers are discovery-eligible and may carry inline dynamic schemas | upstream re-narrowed to `HostBundled \| UserRegistered` | Re-applied; upstream added `UserRegistered`, we union all three. |
| Documents no longer inlined into model context | **not upstream** — upstream still inlines | Upstream added credential redaction (`model_safe_extracted_text`) around the same code but kept the inlining. |
| 500k prompt budget | fork-local product choice | Changes replay digests; not upstream-worthy as a constant. |

### Where upstream moved toward us

- `discover_hosted_mcp_package` now takes a `ResourceScope` — the per-caller discovery our overlay needed.
- `run_context.acting_user_id(fallback)` (#7377) gives one contract derivation for grants/mounts/gates.
- The MCP lane lost budget authority (#7067) — it now gets a narrow reserve/reconcile/release port.

## 4. PRs we should open upstream

Ordered by value. None are pushed; branches are not created.

**PR 1 — `fix(mcp): key discovered hosted-MCP catalogs per (tenant, user, thread)`** · closes #6778
The one that matters. A discovered catalog is published per extension id, so on a multi-principal MCP
server one caller's `tools/list` evicts every other caller's tools, and metadata crosses principals.
Adds `ScopedPackageOverlay` (TTL'd, thread-keyed, bounded) plus turn-start discovery under the caller's
own credential; surface, grants, provider trust, dispatch and egress all read one overlaid view with
global-registry fallback. ~830 lines plus wiring. Ships with the isolation e2e scenario.
*Split candidate:* land the overlay type + registry read path first, the composition wiring second.
*Review note:* to attach the overlay this port turns upstream's `ExtensionCapabilitySurfaceSource`
enum back into a struct. That is a regression in their shape — for the PR, carry the overlay on the
`Management` variant (or a wrapper) instead of flattening the enum. Likewise `grants()` and
`provider_trust()` take `&OverlayScope` where upstream takes `&UserId`; an `impl From<&ResourceScope>`
would keep their call sites unchanged.

**PR 2 — `fix(extensions): merge discovered catalogs instead of replacing them`**
Smaller, independently useful, and a prerequisite for PR 1 being safe. Fresh-wins-per-id superset
instead of wholesale replacement, and a discovered tool whose id matches a reviewed manifest
declaration adopts that declaration's effects and permission (so a `financial` tool cannot be
downgraded by discovery). Host-internal connection templates explicitly do **not** hand over
their permission. Tests included.

**PR 3 — `feat(mcp): opt-in SEP-414 caller attribution on outbound tool calls`**
Providers that declare `[mcp] attribution = "sep414"` receive `_meta` with `io.ironclaw/userId`,
`io.ironclaw/invocationId` and optional `io.ironclaw/threadId` on `tools/list` and `tools/call`.
Strictly opt-in — every existing provider keeps a byte-identical wire shape — and `initialize` is
never stamped. Lets a hosted provider dedupe retried side-effecting calls and scope state per
conversation without inventing its own argument conventions.
Now sits correctly in upstream's module charter: helpers in `jsonrpc`, the stamp decision in `client`,
the flag on the egress plan. Privacy test (`non_opted_provider_gets_no_attribution`) included.

**PR 4 — `fix(attachments): stop inlining extracted document text into model context`**
One PDF is roughly 25k tokens and a job can carry several, so a couple of attachments can consume the
whole context before the model does any work. The stored project path is already in the block; the
agent pages the file with `read_file` instead. Upstream's credential redaction is kept and its test
retargeted to audio transcripts, which still inline.
*Note:* the fork's 500k budget bump is deliberately **not** part of this PR — that is a deployment
choice, and upstream would want it configurable rather than a constant.

**PR 5 — `fix(cli): ironclaw skills list cannot see skills of users created by WebUI login`**
Follow-up to #7168. Runtime skill mounts are now database-backed, but `ironclaw skills list` still
goes through `build_existing_standalone_skill_management_port(owner_id, standalone_storage_root)` —
a disk store under one configured owner. So the CLI cannot show a user that WebUI login minted, and
after #7168 it also cannot show what an agent's own `skill_install` wrote. Fix: read the same store
the runtime writes, discover owners rather than assume one, add `--tenant`/`--user` filters and
`tenant`/`user` fields on the JSON entries.
*File as an issue first* — the storage design is upstream's and they should pick the shape.

**Not proposed upstream:** the bundled `agent-market` extension and the 500k budget. Both are
deployment-specific; they stay fork-only.

## 5. State and what is left

- ✅ All 160 conflicts resolved; `cargo check --workspace --all-targets` clean.
- ✅ Family digests recomputed against the 500k fingerprint (`families/{mod,subagent}.rs`).
- ✅ Merge committed on `sync/upstream-main-2026-09-08`; `deploy/ironclaw2` untouched.
- ✅ `cargo test --workspace --lib`: **64 of 66 suites green**. The two red suites are load flakes, not
  merge regressions — all six named tests pass when run individually, and one of them
  (`filesystem_governor::journal::tests::busy_retry_window_...`, a deadline test) lives in
  `ironclaw_resources`, a crate this fork does not touch at all. Load average during the run was 23–34
  on 8 cores because another build was running on the box.
  One real environment requirement: `runtime_nearai_mcp_prebuild_api_key_is_not_replaced_by_stored_key`
  overflows the debug stack unless `RUST_MIN_STACK` is set — CI sets `67108864`, so set it locally too.
  Run the suite alone and composition is **555 passed / 1 flake**.
- ✅ Binary built (`ironclaw 1.2.0`); `ironclaw doctor` **7 passed / 0 failed / 1 skipped** against the
  live ironclaw2 config.
- ✅ **Deployed.** `ironclaw2.service` now runs `~/ironclaw2-home/bin/ironclaw` via a systemd drop-in
  (`/etc/systemd/system/ironclaw2.service.d/override.conf`). Rollback = delete that drop-in +
  `systemctl daemon-reload && systemctl restart ironclaw2`; the old binary is untouched at
  `~/Developer/ironclaw/target/debug/ironclaw`.
- ✅ Post-cutover: service `active`, `/` and `/health` return 200, `/v2` redirects, migrations applied
  (`root_filesystem_ordered_index_rows` present), no ERROR/panic in the journal. All three fork
  features verified present in the deployed binary (`agent-market` manifest, `io.ironclaw/invocationId`,
  the per-user discovery lane).

One stale fork assertion was removed during the sync: upstream retired
`builtin.outbound_delivery_target_route_current` (it is in their retired-taxonomy ratchet now) while the
fork's policy test still demanded a trigger grant and an approval-gate exemption for it.

### Database

The cutover runs three new forward-only migrations against `ironclaw_reborn2`:

- `migrations/V33__root_filesystem_ordered_index_rows.sql`
- `migrations/V34__root_filesystem_ordered_index_path_collation.sql`
- `crates/loop/ironclaw_hooks/src/postgres_backend/migrations/V1__predicate_state.sql`

Pre-cutover backup taken: `~/backups/ironclaw_reborn2-pre-upstream-sync-20260908-114202.dump`
(`pg_dump -Fc`, 9.1 MB). Restore with `pg_restore --clean --if-exists -d <url> <dump>`.

### Watch items after deploy

1. The `agent-market` extension needs `AGENT_MARKET_MCP_URL`; with it unset the extension exists but
   points nowhere (and a set-but-blank value fails loudly, by design).
2. Upstream's DB-backed skill mounts change where skills live. Existing on-disk user skills on this
   stand may need a migration pass — verify `skill_list` in a real turn after cutover.
3. `ExtensionManifest` gained a required `mcp_attribution` field, so every struct literal must set it.
   If upstream takes PR 3 they will probably want `#[serde(default)]` plus a `Default` impl instead.
