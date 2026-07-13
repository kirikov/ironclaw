//! Ambient grant source for discovered hosted-MCP capabilities.
//!
//! Mirrors [`extension_surface::LocalDevExtensionSurface::grants`] (the
//! ambient-grant pattern already used for installed-extension capabilities)
//! but is keyed by [`HireScope`] and sourced from the SAME
//! `HostedMcpSurfaceOverlay` composition already attaches to `HostRuntime`
//! (`CompositionHostedMcpOverlay`, TTL-cached + single-flighted) — reusing
//! discovery, never adding a second store or scheduled service. This closes
//! F1 (the invoke-path gap tracked by the architectural audit): a discovered
//! hosted-MCP tool the buyer granted this hire is surfaced as
//! `RequiresApproval` (via the SAME `Allow -> RequireApproval` arm every
//! other ambient grant uses, `ironclaw_host_runtime::surface`) and becomes
//! genuinely invocable after approval, instead of surfacing an affordance
//! dispatch can never honor.
//!
//! Mints a grant ONLY for a discovered descriptor whose
//! `default_permission == PermissionMode::Ask`. Belt: discovered hosted-MCP
//! capabilities are Ask-only by construction
//! (`ironclaw_extensions::hosted_mcp_discovery::discovered_capability_manifest`
//! hardcodes it), but a manifest/contract change must not silently mint an
//! ungated grant. A non-Ask descriptor mints nothing: no grant means the
//! authorizer returns `MissingGrant`, which the profile approval gate passes
//! through unchanged (`ProfileApprovalPolicyAuthorizer` only ever upgrades an
//! `Allow`) — closing the bypass at the mint site rather than trusting a
//! downstream gate to catch it.
//!
//! Isolation is structural, matching every other grant this composition
//! mints (`LocalDevExtensionSurface::grants`, `LocalDevCapabilityPolicy::
//! builtin_grants`): the grantee is `Principal::Extension(loop_driver_extension)`,
//! not agent-scoped, but the grant only ever enters a SPECIFIC agent's
//! `ExecutionContext.grants` because it is minted fresh, per call, inside
//! that agent's own `local_dev_visible_capability_request` /
//! `RefreshingLocalDevCapabilityPort::build_inner` — a separate
//! `LoopRunContext` (and therefore a separate `HireScope`) per agent, never
//! shared or cached across agents. `loop_driver_id` is NOT unique per
//! (user, agent) (it names a loop-driver KIND, e.g. a model family), so the
//! `Principal::Extension` grantee alone provides no isolation — the
//! surrounding per-run construction is what does. See
//! `ironclaw_host_runtime::production::tests::hosted_mcp_overlay_wiring::
//! resolve_invocation_registry_isolates_discovered_capabilities_across_agents`
//! and `multi_tenant_turns_see_only_their_own_overlay_capabilities` for the
//! hard regression gates this relies on.
//!
//! Fail-safe: overlay absent, no `agent_id` on scope (`HireScope::from_scope`
//! returns `None`), or discovery errors/times out all fall through to "no
//! grants minted" — a discovered tool then stays surfaced-but-not-invocable
//! (per the surface's `MissingGrant` arm, S2: no ambient grant means it
//! doesn't even surface as askable) — never breaking the turn.

use std::sync::Arc;

use chrono::Utc;
use ironclaw_extensions::ExtensionRegistry;
use ironclaw_host_api::{
    CapabilityGrant, CapabilityGrantId, ExtensionId, GrantConstraints, MountView, NetworkPolicy,
    PermissionMode, Principal, ResourceScope,
};
use ironclaw_host_runtime::{
    HireScope, HostedMcpSurfaceOverlay, discover_overlay_capabilities_for_hire,
};

/// Time bound on the ambient grant this source mints (S2/M2 belt — see the
/// `expires_at` doc comment in `grants_for_scope`). The grant is re-minted
/// fresh on every `build_inner` tick and does not gate resume (the one-shot
/// lease does), so this only needs to comfortably outlive one turn's
/// dispatch latency, not a whole session.
const AMBIENT_GRANT_TTL: chrono::Duration = chrono::Duration::minutes(5);

#[derive(Clone)]
pub(in crate::runtime) struct DiscoveredCapabilityGrantSource {
    overlay: Option<Arc<dyn HostedMcpSurfaceOverlay>>,
}

impl DiscoveredCapabilityGrantSource {
    pub(in crate::runtime) fn new(overlay: Option<Arc<dyn HostedMcpSurfaceOverlay>>) -> Self {
        Self { overlay }
    }

    /// Discovers this hire's hosted-MCP tools (via the shared overlay — a
    /// cache hit in the common case, since `HostRuntime::visible_capabilities`
    /// discovers the identical scope moments later when the caller builds
    /// the surface from the SAME context) and mints one ambient grant per
    /// `Ask`-permission descriptor, scoped to `grantee`.
    pub(in crate::runtime) async fn grants_for_scope(
        &self,
        registry: &ExtensionRegistry,
        scope: &ResourceScope,
        grantee: &ExtensionId,
    ) -> Vec<CapabilityGrant> {
        let Some(overlay) = self.overlay.as_deref() else {
            return Vec::new();
        };
        let Some(hire) = HireScope::from_scope(scope) else {
            return Vec::new();
        };
        let discovered = discover_overlay_capabilities_for_hire(registry, overlay, &hire).await;
        discovered
            .into_iter()
            .filter(|descriptor| descriptor.default_permission == PermissionMode::Ask)
            .map(|descriptor| {
                // Grant breadth stays package-scoped: network is the
                // discovered tool's own credential audiences (the package's
                // MCP host), secrets are the tool's own credential handles —
                // never a wider grant than the descriptor itself declares.
                let allowed_targets = descriptor
                    .runtime_credentials
                    .iter()
                    .map(|credential| credential.audience.clone())
                    .collect::<Vec<_>>();
                let secrets = descriptor
                    .runtime_credentials
                    .iter()
                    .map(|credential| credential.handle.clone())
                    .collect::<Vec<_>>();
                CapabilityGrant {
                    id: CapabilityGrantId::new(),
                    capability: descriptor.id,
                    grantee: Principal::Extension(grantee.clone()),
                    issued_by: Principal::HostRuntime,
                    constraints: GrantConstraints {
                        allowed_effects: descriptor.effects,
                        mounts: MountView::default(),
                        network: NetworkPolicy {
                            allowed_targets,
                            deny_private_ip_ranges: true,
                            max_egress_bytes: None,
                        },
                        secrets,
                        resource_ceiling: None,
                        // Ambient, turn-scoped: not a one-shot approval
                        // lease (that is Half-3, the separate
                        // approval->lease bridge in `runtime/approval.rs`).
                        // `max_invocations: None` is what lets the profile
                        // approval gate's precedence chain reach the
                        // `Ask`-permission `RequireApproval` step instead of
                        // being read as an already-consumed one-shot grant.
                        // "Turn-scoped" is enforced structurally (minted
                        // fresh per `build_inner` refresh, never persisted
                        // past that `ExecutionContext`) AND, as a REAL belt,
                        // by this `expires_at` — `loop_driver_id` is
                        // confirmed non-unique per (user, agent), so the
                        // grantee principal alone provides no isolation;
                        // this bounds the window an authorizer would honor
                        // the grant even if the structural per-run scoping
                        // were ever bypassed (e.g. a future caching bug).
                        // Enforced at `ironclaw_authorization::grant_is_active`.
                        // Comfortably above one turn's dispatch latency,
                        // well short of a human noticing/re-approving.
                        // TODO(tracked follow-up): the full agent-scoped
                        // `GrantConstraints` principal (stronger than a time
                        // bound) has no schema precedent in this codebase's
                        // grant model today — out of scope for "reuse
                        // existing" in this slice.
                        expires_at: Some(Utc::now() + AMBIENT_GRANT_TTL),
                        max_invocations: None,
                    },
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironclaw_extensions::ExtensionPackage;
    use ironclaw_host_api::{
        AgentId, CapabilityDescriptor, CapabilityId, EffectKind, NetworkScheme,
        NetworkTargetPattern, ProjectId, RuntimeCredentialRequirement,
        RuntimeCredentialRequirementSource, RuntimeCredentialTarget, RuntimeKind, SecretHandle,
        TenantId, TrustClass, UserId,
    };
    use ironclaw_host_runtime::HostedMcpOverlayError;

    fn scope(agent: Option<&str>) -> ResourceScope {
        ResourceScope {
            tenant_id: TenantId::new("acme").unwrap(),
            user_id: UserId::new("buyer-1").unwrap(),
            agent_id: agent.map(|value| AgentId::new(value).unwrap()),
            project_id: Some(ProjectId::new("proj-1").unwrap()),
            mission_id: None,
            thread_id: None,
            invocation_id: ironclaw_host_api::InvocationId::new(),
        }
    }

    fn discovered_descriptor(id: &str, permission: PermissionMode) -> CapabilityDescriptor {
        CapabilityDescriptor {
            id: CapabilityId::new(id).unwrap(),
            provider: ExtensionId::new("notion").unwrap(),
            runtime: RuntimeKind::Mcp,
            trust_ceiling: TrustClass::UserTrusted,
            description: "discovered tool".to_string(),
            parameters_schema: serde_json::json!({"type": "object"}),
            effects: vec![EffectKind::DispatchCapability, EffectKind::Network],
            default_permission: permission,
            runtime_credentials: vec![RuntimeCredentialRequirement {
                handle: SecretHandle::new("notion_token").unwrap(),
                source: RuntimeCredentialRequirementSource::SecretHandle,
                provider_scopes: Vec::new(),
                audience: NetworkTargetPattern {
                    scheme: Some(NetworkScheme::Https),
                    host_pattern: "mcp.notion.com".to_string(),
                    port: None,
                },
                target: RuntimeCredentialTarget::Header {
                    name: "authorization".to_string(),
                    prefix: Some("Bearer ".to_string()),
                },
                required: true,
            }],
            resource_profile: None,
        }
    }

    struct StaticOverlay {
        descriptors: Vec<CapabilityDescriptor>,
    }

    #[async_trait::async_trait]
    impl HostedMcpSurfaceOverlay for StaticOverlay {
        async fn overlay_capabilities(
            &self,
            _hire: &HireScope,
            _package: &ExtensionPackage,
        ) -> Result<Vec<CapabilityDescriptor>, HostedMcpOverlayError> {
            Ok(self.descriptors.clone())
        }
    }

    fn notion_registry() -> ExtensionRegistry {
        const MANIFEST: &str = r#"
schema_version = "reborn.extension_manifest.v2"
id = "notion"
name = "Notion"
version = "1.0.0"
description = "test hosted mcp"
trust = "third_party"

[runtime]
kind = "mcp"
transport = "http"
url = "https://mcp.notion.com/mcp"

[[capabilities]]
id = "notion.notion-fetch"
description = "floor capability"
effects = ["dispatch_capability", "network"]
default_permission = "ask"
visibility = "model"
input_schema_ref = "schemas/notion/fetch.input.json"
output_schema_ref = "schemas/notion/fetch.output.json"
"#;
        let manifest = ironclaw_extensions::ExtensionManifest::parse(
            MANIFEST,
            ironclaw_extensions::ManifestSource::HostBundled,
            &ironclaw_host_api::HostPortCatalog::default(),
        )
        .unwrap();
        let package = ExtensionPackage::from_manifest(
            manifest,
            ironclaw_host_api::VirtualPath::new("/system/extensions/notion").unwrap(),
        )
        .unwrap();
        let mut registry = ExtensionRegistry::new();
        registry.insert(package).unwrap();
        registry
    }

    #[tokio::test]
    async fn mints_a_grant_only_for_ask_permission_discovered_descriptors() {
        let source = DiscoveredCapabilityGrantSource::new(Some(Arc::new(StaticOverlay {
            descriptors: vec![
                discovered_descriptor("notion.live-search", PermissionMode::Ask),
                discovered_descriptor("notion.auto-sync", PermissionMode::Allow),
            ],
        })));
        let grantee = ExtensionId::new("loop-driver").unwrap();

        let grants = source
            .grants_for_scope(&notion_registry(), &scope(Some("agent-1")), &grantee)
            .await;

        assert_eq!(
            grants.len(),
            1,
            "only the Ask-permission descriptor mints a grant"
        );
        let grant = &grants[0];
        assert_eq!(grant.capability.as_str(), "notion.live-search");
        assert_eq!(grant.grantee, Principal::Extension(grantee));
        assert_eq!(grant.issued_by, Principal::HostRuntime);
        assert_eq!(grant.constraints.max_invocations, None);
        assert_eq!(
            grant.constraints.secrets,
            vec![SecretHandle::new("notion_token").unwrap()]
        );
        assert_eq!(grant.constraints.network.allowed_targets.len(), 1);
        assert!(grant.constraints.network.deny_private_ip_ranges);
        // S2/M2 belt (review item 2): the ambient grant is time-bounded even
        // though it is `max_invocations: None` (ambient, not one-shot) —
        // `loop_driver_id` is non-unique per (user, agent), so this
        // `expires_at` is a real backstop, not cosmetic.
        let expires_at = grant
            .constraints
            .expires_at
            .expect("ambient discovered-capability grant must carry an expires_at belt");
        let now = Utc::now();
        assert!(
            expires_at > now,
            "expires_at must be in the future when minted"
        );
        assert!(
            expires_at <= now + AMBIENT_GRANT_TTL + chrono::Duration::seconds(5),
            "expires_at must be bounded to roughly the turn-lifetime TTL, not open-ended"
        );
    }

    #[tokio::test]
    async fn mints_nothing_without_an_agent_scope() {
        let source = DiscoveredCapabilityGrantSource::new(Some(Arc::new(StaticOverlay {
            descriptors: vec![discovered_descriptor(
                "notion.live-search",
                PermissionMode::Ask,
            )],
        })));
        let grantee = ExtensionId::new("loop-driver").unwrap();

        let grants = source
            .grants_for_scope(&notion_registry(), &scope(None), &grantee)
            .await;

        assert!(grants.is_empty(), "no agent_id must never mint a grant");
    }

    #[tokio::test]
    async fn mints_nothing_without_an_attached_overlay() {
        let source = DiscoveredCapabilityGrantSource::new(None);
        let grantee = ExtensionId::new("loop-driver").unwrap();

        let grants = source
            .grants_for_scope(&notion_registry(), &scope(Some("agent-1")), &grantee)
            .await;

        assert!(grants.is_empty());
    }
}
