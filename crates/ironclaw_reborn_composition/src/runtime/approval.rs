use std::sync::Arc;

use async_trait::async_trait;
use ironclaw_approvals::{LeaseApproval, permission_mode_allows_persistent_approval};
use ironclaw_extensions::ExtensionRegistry;
use ironclaw_host_api::{EffectKind, MountView, Principal};
use ironclaw_product_workflow::{
    ApprovalGateRecord, ApprovalInteractionRejectionKind, ApprovalLeaseTermsProvider,
    ProductWorkflowError,
};

use crate::local_dev_capability_policy::{
    LocalDevApprovalPolicyAction, LocalDevCapabilityPolicy, LocalDevCapabilityPolicyError,
    local_dev_one_shot_lease_approval,
};
use crate::outbound::OUTBOUND_DELIVERY_TARGET_SET_CAPABILITY_ID;

use super::local_dev::discovered_capability_grants::DiscoveredCapabilityGrantSource;
use super::local_dev::extension_surface::LocalDevExtensionSurfaceSource;

pub(super) struct LocalDevApprovalLeaseTermsProvider {
    policy: Arc<LocalDevCapabilityPolicy>,
    registry: Arc<ExtensionRegistry>,
    workspace_mounts: MountView,
    skill_mounts: MountView,
    memory_mounts: MountView,
    system_extensions_lifecycle_mounts: MountView,
    extension_surface_source: LocalDevExtensionSurfaceSource,
    discovered_capability_grants: DiscoveredCapabilityGrantSource,
}

impl LocalDevApprovalLeaseTermsProvider {
    #[allow(clippy::too_many_arguments)]
    // arch-exempt: too_many_args, pre-existing constructor already at 7 args
    // before this slice added the 8th (discovered_capability_grants); needs
    // a config-bundle struct, tracked with the rest of this provider's
    // argument creep, plan #4539
    pub(super) fn new(
        policy: Arc<LocalDevCapabilityPolicy>,
        registry: Arc<ExtensionRegistry>,
        workspace_mounts: MountView,
        skill_mounts: MountView,
        memory_mounts: MountView,
        system_extensions_lifecycle_mounts: MountView,
        extension_surface_source: LocalDevExtensionSurfaceSource,
        discovered_capability_grants: DiscoveredCapabilityGrantSource,
    ) -> Self {
        Self {
            policy,
            registry,
            workspace_mounts,
            skill_mounts,
            memory_mounts,
            system_extensions_lifecycle_mounts,
            extension_surface_source,
            discovered_capability_grants,
        }
    }

    /// Third tier (after the static policy and the installed-extension
    /// surface): lease terms for a discovered hosted-MCP capability. Mints
    /// the SAME ambient-grant shape `DiscoveredCapabilityGrantSource` would
    /// put into a fresh turn context, then converts it into a one-shot
    /// lease via `local_dev_one_shot_lease_approval` — matching the
    /// extension-surface tier's own shape. `gate.resource_scope()` (not the
    /// gate's `requested_by` principal) is what carries `agent_id`, so this
    /// is the layer that resolves `HireScope`.
    async fn discovered_capability_lease_terms_for(
        &self,
        gate: &ApprovalGateRecord,
        action: LocalDevApprovalPolicyAction<'_>,
    ) -> Result<Option<LeaseApproval>, ProductWorkflowError> {
        let Principal::Extension(extension_id) = &gate.request().requested_by else {
            return Ok(None);
        };
        let capability = action.capability();
        let grants = self
            .discovered_capability_grants
            .grants_for_scope(&self.registry, gate.resource_scope(), extension_id)
            .await;
        let Some(grant) = grants
            .into_iter()
            .find(|grant| grant.capability == *capability)
        else {
            return Ok(None);
        };
        if action.is_spawn_capability() {
            // M1 invariant: discovered hosted-MCP capabilities are
            // dispatch-only (`runtime = Mcp`) and never declare
            // `SpawnProcess`; a spawn action reaching here for a discovered
            // id is a host bug, not a legitimate lease request.
            tracing::error!(
                capability = %capability,
                "discovered hosted-MCP capability spawn lease is unsupported"
            );
            return Err(lease_terms_unavailable());
        }
        Ok(Some(local_dev_one_shot_lease_approval(grant.constraints)))
    }

    async fn extension_lease_terms_for_active_capability(
        &self,
        gate: &ApprovalGateRecord,
        action: LocalDevApprovalPolicyAction<'_>,
    ) -> Result<Option<LeaseApproval>, ProductWorkflowError> {
        let capability = action.capability();
        let Principal::Extension(extension_id) = &gate.request().requested_by else {
            return Ok(None);
        };
        let surface = self
            .extension_surface_source
            .snapshot()
            .await
            .map_err(|error| {
                tracing::error!(%error, "local-dev extension approval lease terms are unavailable");
                lease_terms_unavailable()
            })?;
        let Some(grant) = surface
            .grants(extension_id)
            .into_iter()
            .find(|grant| grant.capability == *capability)
        else {
            return Ok(None);
        };
        if action.is_spawn_capability()
            && !grant
                .constraints
                .allowed_effects
                .contains(&EffectKind::SpawnProcess)
        {
            tracing::error!(
                capability = %capability,
                "local-dev extension spawn approval lease lacks SpawnProcess"
            );
            return Err(lease_terms_unavailable());
        }
        Ok(Some(local_dev_one_shot_lease_approval(grant.constraints)))
    }

    async fn active_extension_persistent_approval_allowed(
        &self,
        action: LocalDevApprovalPolicyAction<'_>,
    ) -> Result<bool, ProductWorkflowError> {
        let surface = self
            .extension_surface_source
            .snapshot()
            .await
            .map_err(|error| {
                tracing::error!(%error, "local-dev extension approval surface is unavailable");
                lease_terms_unavailable()
            })?;
        let Some(capability) = surface.capability(action.capability()) else {
            return Ok(false);
        };
        if action.is_spawn_capability() && !capability.effects.contains(&EffectKind::SpawnProcess) {
            tracing::error!(
                capability = %action.capability(),
                "local-dev extension spawn persistent approval lacks SpawnProcess"
            );
            return Ok(false);
        }
        Ok(permission_mode_allows_persistent_approval(
            capability.default_permission,
        ))
    }
}

#[async_trait]
impl ApprovalLeaseTermsProvider for LocalDevApprovalLeaseTermsProvider {
    async fn lease_terms_for(
        &self,
        gate: &ApprovalGateRecord,
    ) -> Result<ironclaw_approvals::LeaseApproval, ProductWorkflowError> {
        let action = LocalDevApprovalPolicyAction::from_host_action(gate.request().action.as_ref())
            .ok_or(ProductWorkflowError::ApprovalInteractionRejected {
                kind: ApprovalInteractionRejectionKind::UnsupportedAction,
            })?;
        if action.is_spawn_capability()
            && let Some(approval) = self
                .extension_lease_terms_for_active_capability(gate, action)
                .await?
        {
            return Ok(approval);
        }
        match self.policy.lease_approval_for(
            action,
            &self.workspace_mounts,
            &self.skill_mounts,
            &self.memory_mounts,
            &self.system_extensions_lifecycle_mounts,
        ) {
            Ok(approval) => Ok(approval),
            Err(LocalDevCapabilityPolicyError::MissingGrant { .. }) => {
                // Tier 2: installed-extension surface.
                if let Some(approval) = self
                    .extension_lease_terms_for_active_capability(gate, action)
                    .await?
                {
                    return Ok(approval);
                }
                // Tier 3 (C1/Half-3): a discovered hosted-MCP capability is
                // in neither the static policy nor the installed-extension
                // surface — both tiers fall through for it by construction
                // (it is not an installed extension's capability, it is a
                // per-hire, live-discovered one). Without this tier,
                // resume hits `LeaseTermsUnavailable` even though invoke
                // correctly gated it — the C1 bug in the approval-bridge
                // half of the invoke path.
                self.discovered_capability_lease_terms_for(gate, action)
                    .await?
                    .ok_or_else(lease_terms_unavailable)
            }
            Err(error) => {
                tracing::error!(%error, "local-dev approval lease terms are unavailable");
                Err(lease_terms_unavailable())
            }
        }
    }

    async fn persistent_approval_allowed(
        &self,
        gate: &ApprovalGateRecord,
    ) -> Result<(), ProductWorkflowError> {
        let action = LocalDevApprovalPolicyAction::from_host_action(gate.request().action.as_ref())
            .ok_or(ProductWorkflowError::ApprovalInteractionRejected {
                kind: ApprovalInteractionRejectionKind::UnsupportedAction,
            })?;
        if let Some(descriptor) = self.registry.get_capability(action.capability_id()) {
            if permission_mode_allows_persistent_approval(descriptor.default_permission) {
                return Ok(());
            }
            return Err(ProductWorkflowError::ApprovalInteractionRejected {
                kind: ApprovalInteractionRejectionKind::AlwaysAllowUnsupported,
            });
        }
        if action.capability_id().as_str() == OUTBOUND_DELIVERY_TARGET_SET_CAPABILITY_ID {
            match self.policy.lease_approval_for(
                action,
                &self.workspace_mounts,
                &self.skill_mounts,
                &self.memory_mounts,
                &self.system_extensions_lifecycle_mounts,
            ) {
                Ok(_) => return Ok(()),
                Err(LocalDevCapabilityPolicyError::MissingGrant { .. }) => {}
                Err(error) => {
                    tracing::error!(
                        %error,
                        "local-dev persistent approval terms are unavailable"
                    );
                    return Err(lease_terms_unavailable());
                }
            }
        }
        if self
            .active_extension_persistent_approval_allowed(action)
            .await?
        {
            Ok(())
        } else {
            Err(ProductWorkflowError::ApprovalInteractionRejected {
                kind: ApprovalInteractionRejectionKind::AlwaysAllowUnsupported,
            })
        }
    }
}

fn lease_terms_unavailable() -> ProductWorkflowError {
    ProductWorkflowError::ApprovalInteractionRejected {
        kind: ApprovalInteractionRejectionKind::LeaseTermsUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ironclaw_host_api::{
        Action, ApprovalRequest, ApprovalRequestId, CapabilityId, CorrelationId, EffectKind,
        ExtensionId, InvocationId, PermissionMode, ResourceEstimate, ResourceScope, SecretHandle,
        TenantId, ThreadId, UserId,
    };
    use ironclaw_product_workflow::approval_gate_ref;
    use ironclaw_turns::{GateRef, TurnRunId};

    use crate::extension_host::extension_lifecycle::ActiveExtensionCapability;
    use crate::local_dev_capability_policy::local_dev_capability_policy;
    use crate::runtime::local_dev::extension_surface::{
        LocalDevExtensionSurface, LocalDevExtensionSurfaceSource,
    };

    use super::*;

    #[tokio::test]
    async fn extension_capability_missing_from_builtin_policy_gets_one_shot_lease_terms() {
        let capability = CapabilityId::new("gmail.send_message").expect("capability id");
        let provider = ExtensionId::new("gmail").expect("provider id");
        let caller = ExtensionId::new("caller").expect("caller id");
        let source = LocalDevExtensionSurfaceSource::from_surface(
            LocalDevExtensionSurface::from_active_capabilities(vec![ActiveExtensionCapability {
                id: capability.clone(),
                provider,
                effects: vec![EffectKind::Network, EffectKind::UseSecret],
                default_permission: PermissionMode::Allow,
                runtime_credentials: Vec::new(),
            }]),
        );
        let terms_provider = LocalDevApprovalLeaseTermsProvider::new(
            Arc::new(local_dev_capability_policy().expect("policy parses")),
            Arc::new(ExtensionRegistry::new()),
            MountView::default(),
            MountView::default(),
            MountView::default(),
            MountView::default(),
            source,
            DiscoveredCapabilityGrantSource::new(None),
        );
        let request_id = ApprovalRequestId::new();
        let gate = approval_gate_record(
            request_id,
            Principal::Extension(caller),
            Action::Dispatch {
                capability: capability.clone(),
                estimated_resources: ResourceEstimate::default(),
            },
        );

        let approval = terms_provider
            .lease_terms_for(&gate)
            .await
            .expect("extension lease terms");

        assert_eq!(approval.issued_by, Principal::HostRuntime);
        assert_eq!(approval.constraints.max_invocations, Some(1));
        assert_eq!(
            approval.constraints.allowed_effects,
            vec![EffectKind::Network, EffectKind::UseSecret]
        );
        assert_eq!(
            approval.constraints.secrets,
            Vec::<SecretHandle>::new(),
            "test capability has no runtime credential handles"
        );
    }

    #[tokio::test]
    async fn extension_spawn_capability_uses_extension_surface_terms_before_default_policy() {
        let capability = CapabilityId::new("gmail.send_message").expect("capability id");
        let provider = ExtensionId::new("gmail").expect("provider id");
        let caller = ExtensionId::new("caller").expect("caller id");
        let secret = SecretHandle::new("gmail_token").expect("secret handle");
        let source = LocalDevExtensionSurfaceSource::from_surface(
            LocalDevExtensionSurface::from_active_capabilities(vec![ActiveExtensionCapability {
                id: capability.clone(),
                provider,
                effects: vec![
                    EffectKind::SpawnProcess,
                    EffectKind::Network,
                    EffectKind::UseSecret,
                ],
                default_permission: PermissionMode::Allow,
                runtime_credentials: vec![ironclaw_host_api::RuntimeCredentialRequirement {
                    handle: secret.clone(),
                    source: ironclaw_host_api::RuntimeCredentialRequirementSource::SecretHandle,
                    provider_scopes: Vec::new(),
                    audience: ironclaw_host_api::NetworkTargetPattern {
                        scheme: Some(ironclaw_host_api::NetworkScheme::Https),
                        host_pattern: "gmail.googleapis.com".to_string(),
                        port: None,
                    },
                    target: ironclaw_host_api::RuntimeCredentialTarget::Header {
                        name: "authorization".to_string(),
                        prefix: Some("Bearer ".to_string()),
                    },
                    required: true,
                }],
            }]),
        );
        let terms_provider = LocalDevApprovalLeaseTermsProvider::new(
            Arc::new(local_dev_capability_policy().expect("policy parses")),
            Arc::new(ExtensionRegistry::new()),
            MountView::default(),
            MountView::default(),
            MountView::default(),
            MountView::default(),
            source,
            DiscoveredCapabilityGrantSource::new(None),
        );
        let request_id = ApprovalRequestId::new();
        let gate = approval_gate_record(
            request_id,
            Principal::Extension(caller),
            Action::SpawnCapability {
                capability: capability.clone(),
                estimated_resources: ResourceEstimate::default(),
            },
        );

        let approval = terms_provider
            .lease_terms_for(&gate)
            .await
            .expect("extension spawn lease terms");

        assert_eq!(approval.issued_by, Principal::HostRuntime);
        assert_eq!(approval.constraints.max_invocations, Some(1));
        assert_eq!(
            approval.constraints.allowed_effects,
            vec![
                EffectKind::SpawnProcess,
                EffectKind::Network,
                EffectKind::UseSecret
            ]
        );
        assert_eq!(approval.constraints.secrets, vec![secret]);
    }

    #[tokio::test]
    async fn active_extension_capability_allows_persistent_approval_when_manifest_allows() {
        let capability = CapabilityId::new("gmail.send_message").expect("capability id");
        let provider = ExtensionId::new("gmail").expect("provider id");
        let caller = ExtensionId::new("caller").expect("caller id");
        let source = LocalDevExtensionSurfaceSource::from_surface(
            LocalDevExtensionSurface::from_active_capabilities(vec![ActiveExtensionCapability {
                id: capability.clone(),
                provider,
                effects: vec![EffectKind::Network],
                default_permission: PermissionMode::Allow,
                runtime_credentials: Vec::new(),
            }]),
        );
        let terms_provider = LocalDevApprovalLeaseTermsProvider::new(
            Arc::new(local_dev_capability_policy().expect("policy parses")),
            Arc::new(ExtensionRegistry::new()),
            MountView::default(),
            MountView::default(),
            MountView::default(),
            MountView::default(),
            source,
            DiscoveredCapabilityGrantSource::new(None),
        );
        let gate = approval_gate_record(
            ApprovalRequestId::new(),
            Principal::Extension(caller),
            Action::Dispatch {
                capability,
                estimated_resources: ResourceEstimate::default(),
            },
        );

        terms_provider
            .persistent_approval_allowed(&gate)
            .await
            .expect("active extension persistent approval should be allowed");
    }

    #[tokio::test]
    async fn active_extension_capability_allows_persistent_approval_when_manifest_asks() {
        let capability = CapabilityId::new("gmail.send_message").expect("capability id");
        let provider = ExtensionId::new("gmail").expect("provider id");
        let caller = ExtensionId::new("caller").expect("caller id");
        let source = LocalDevExtensionSurfaceSource::from_surface(
            LocalDevExtensionSurface::from_active_capabilities(vec![ActiveExtensionCapability {
                id: capability.clone(),
                provider,
                effects: vec![EffectKind::Network],
                default_permission: PermissionMode::Ask,
                runtime_credentials: Vec::new(),
            }]),
        );
        let terms_provider = LocalDevApprovalLeaseTermsProvider::new(
            Arc::new(local_dev_capability_policy().expect("policy parses")),
            Arc::new(ExtensionRegistry::new()),
            MountView::default(),
            MountView::default(),
            MountView::default(),
            MountView::default(),
            source,
            DiscoveredCapabilityGrantSource::new(None),
        );
        let gate = approval_gate_record(
            ApprovalRequestId::new(),
            Principal::Extension(caller),
            Action::Dispatch {
                capability,
                estimated_resources: ResourceEstimate::default(),
            },
        );

        terms_provider
            .persistent_approval_allowed(&gate)
            .await
            .expect("active extension default ask should allow explicit persistent approval");
    }

    #[tokio::test]
    async fn outbound_delivery_target_set_allows_persistent_approval() {
        let capability =
            CapabilityId::new(OUTBOUND_DELIVERY_TARGET_SET_CAPABILITY_ID).expect("capability id");
        let caller = ExtensionId::new("loop-driver").expect("caller id");
        let terms_provider = LocalDevApprovalLeaseTermsProvider::new(
            Arc::new(local_dev_capability_policy().expect("policy parses")),
            Arc::new(ExtensionRegistry::new()),
            MountView::default(),
            MountView::default(),
            MountView::default(),
            MountView::default(),
            LocalDevExtensionSurfaceSource::default(),
            DiscoveredCapabilityGrantSource::new(None),
        );
        let gate = approval_gate_record(
            ApprovalRequestId::new(),
            Principal::Extension(caller),
            Action::Dispatch {
                capability,
                estimated_resources: ResourceEstimate::default(),
            },
        );

        terms_provider
            .persistent_approval_allowed(&gate)
            .await
            .expect("outbound delivery target set should allow persistent approval");
    }

    #[tokio::test]
    async fn active_extension_capability_rejects_persistent_approval_when_manifest_denies() {
        let capability = CapabilityId::new("gmail.send_message").expect("capability id");
        let provider = ExtensionId::new("gmail").expect("provider id");
        let caller = ExtensionId::new("caller").expect("caller id");
        let source = LocalDevExtensionSurfaceSource::from_surface(
            LocalDevExtensionSurface::from_active_capabilities(vec![ActiveExtensionCapability {
                id: capability.clone(),
                provider,
                effects: vec![EffectKind::Network],
                default_permission: PermissionMode::Deny,
                runtime_credentials: Vec::new(),
            }]),
        );
        let terms_provider = LocalDevApprovalLeaseTermsProvider::new(
            Arc::new(local_dev_capability_policy().expect("policy parses")),
            Arc::new(ExtensionRegistry::new()),
            MountView::default(),
            MountView::default(),
            MountView::default(),
            MountView::default(),
            source,
            DiscoveredCapabilityGrantSource::new(None),
        );
        let gate = approval_gate_record(
            ApprovalRequestId::new(),
            Principal::Extension(caller),
            Action::Dispatch {
                capability,
                estimated_resources: ResourceEstimate::default(),
            },
        );

        let error = terms_provider
            .persistent_approval_allowed(&gate)
            .await
            .expect_err("active extension default deny should reject persistent approval");

        assert!(matches!(
            error,
            ProductWorkflowError::ApprovalInteractionRejected {
                kind: ApprovalInteractionRejectionKind::AlwaysAllowUnsupported
            }
        ));
    }

    fn approval_gate_record(
        request_id: ApprovalRequestId,
        requested_by: Principal,
        action: Action,
    ) -> ApprovalGateRecord {
        let resource_scope = ResourceScope {
            tenant_id: TenantId::new("tenant").expect("tenant id"),
            user_id: UserId::new("user").expect("user id"),
            agent_id: None,
            project_id: None,
            mission_id: None,
            thread_id: Some(ThreadId::new("thread").expect("thread id")),
            invocation_id: InvocationId::new(),
        };
        let gate_ref: GateRef = approval_gate_ref(request_id).expect("approval gate ref");
        ApprovalGateRecord::new(
            resource_scope,
            TurnRunId::new(),
            gate_ref,
            ApprovalRequest {
                id: request_id,
                correlation_id: CorrelationId::new(),
                requested_by,
                action: Box::new(action),
                invocation_fingerprint: None,
                reason: "approval required".to_string(),
                reusable_scope: None,
            },
        )
        .expect("approval gate record")
    }

    /// Like `approval_gate_record`, but with an `agent_id` on the resource
    /// scope — needed to reach `HireScope::from_scope` for the discovered-
    /// capability lease-terms tier.
    fn approval_gate_record_with_agent(
        request_id: ApprovalRequestId,
        requested_by: Principal,
        action: Action,
        agent: &str,
    ) -> ApprovalGateRecord {
        let resource_scope = ResourceScope {
            tenant_id: TenantId::new("tenant").expect("tenant id"),
            user_id: UserId::new("user").expect("user id"),
            agent_id: Some(ironclaw_host_api::AgentId::new(agent).expect("agent id")),
            project_id: None,
            mission_id: None,
            thread_id: Some(ThreadId::new("thread").expect("thread id")),
            invocation_id: InvocationId::new(),
        };
        let gate_ref: GateRef = approval_gate_ref(request_id).expect("approval gate ref");
        ApprovalGateRecord::new(
            resource_scope,
            TurnRunId::new(),
            gate_ref,
            ApprovalRequest {
                id: request_id,
                correlation_id: CorrelationId::new(),
                requested_by,
                action: Box::new(action),
                invocation_fingerprint: None,
                reason: "approval required".to_string(),
                reusable_scope: None,
            },
        )
        .expect("approval gate record")
    }

    struct StaticOverlay {
        descriptors: Vec<ironclaw_host_api::CapabilityDescriptor>,
    }

    #[async_trait]
    impl ironclaw_host_runtime::HostedMcpSurfaceOverlay for StaticOverlay {
        async fn overlay_capabilities(
            &self,
            _hire: &ironclaw_host_runtime::HireScope,
            _package: &ironclaw_extensions::ExtensionPackage,
        ) -> Result<
            Vec<ironclaw_host_api::CapabilityDescriptor>,
            ironclaw_host_runtime::HostedMcpOverlayError,
        > {
            Ok(self.descriptors.clone())
        }
    }

    fn notion_registry_with_hosted_mcp_package() -> ExtensionRegistry {
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
        .expect("manifest parses");
        let package = ironclaw_extensions::ExtensionPackage::from_manifest(
            manifest,
            ironclaw_host_api::VirtualPath::new("/system/extensions/notion").expect("root"),
        )
        .expect("package builds");
        let mut registry = ExtensionRegistry::new();
        registry.insert(package).expect("insert provider");
        registry
    }

    fn discovered_descriptor(id: &str) -> ironclaw_host_api::CapabilityDescriptor {
        ironclaw_host_api::CapabilityDescriptor {
            id: CapabilityId::new(id).expect("capability id"),
            provider: ExtensionId::new("notion").expect("provider id"),
            runtime: ironclaw_host_api::RuntimeKind::Mcp,
            trust_ceiling: ironclaw_host_api::TrustClass::UserTrusted,
            description: "discovered tool".to_string(),
            parameters_schema: serde_json::json!({"type": "object"}),
            effects: vec![EffectKind::DispatchCapability, EffectKind::Network],
            default_permission: PermissionMode::Ask,
            runtime_credentials: Vec::new(),
            resource_profile: None,
        }
    }

    /// C1/Half-3 regression: a discovered hosted-MCP capability falls
    /// through both the static policy and the installed-extension surface
    /// (neither tier knows about it), so before this tier existed the
    /// approval bridge returned `LeaseTermsUnavailable` even though invoke
    /// correctly raised the gate — resume could never actually complete.
    #[tokio::test]
    async fn discovered_capability_gets_one_shot_lease_terms() {
        let capability = CapabilityId::new("notion.live-search").expect("capability id");
        let caller = ExtensionId::new("loop-driver").expect("caller id");
        let overlay = StaticOverlay {
            descriptors: vec![discovered_descriptor("notion.live-search")],
        };
        let terms_provider = LocalDevApprovalLeaseTermsProvider::new(
            Arc::new(local_dev_capability_policy().expect("policy parses")),
            Arc::new(notion_registry_with_hosted_mcp_package()),
            MountView::default(),
            MountView::default(),
            MountView::default(),
            MountView::default(),
            LocalDevExtensionSurfaceSource::default(),
            DiscoveredCapabilityGrantSource::new(Some(Arc::new(overlay))),
        );
        let request_id = ApprovalRequestId::new();
        let gate = approval_gate_record_with_agent(
            request_id,
            Principal::Extension(caller),
            Action::Dispatch {
                capability: capability.clone(),
                estimated_resources: ResourceEstimate::default(),
            },
            "agent-1",
        );

        let approval = terms_provider
            .lease_terms_for(&gate)
            .await
            .expect("discovered capability lease terms");

        assert_eq!(approval.issued_by, Principal::HostRuntime);
        assert_eq!(approval.constraints.max_invocations, Some(1));
        assert_eq!(
            approval.constraints.allowed_effects,
            vec![EffectKind::DispatchCapability, EffectKind::Network]
        );
    }

    /// Fail-safe: no overlay attached (or no discovery match) still fails
    /// closed with `LeaseTermsUnavailable`, not a panic or a silently
    /// invented grant.
    #[tokio::test]
    async fn unknown_capability_still_fails_lease_terms_unavailable() {
        let capability = CapabilityId::new("notion.hallucinated-tool").expect("capability id");
        let caller = ExtensionId::new("loop-driver").expect("caller id");
        let terms_provider = LocalDevApprovalLeaseTermsProvider::new(
            Arc::new(local_dev_capability_policy().expect("policy parses")),
            Arc::new(notion_registry_with_hosted_mcp_package()),
            MountView::default(),
            MountView::default(),
            MountView::default(),
            MountView::default(),
            LocalDevExtensionSurfaceSource::default(),
            DiscoveredCapabilityGrantSource::new(None),
        );
        let gate = approval_gate_record_with_agent(
            ApprovalRequestId::new(),
            Principal::Extension(caller),
            Action::Dispatch {
                capability,
                estimated_resources: ResourceEstimate::default(),
            },
            "agent-1",
        );

        let error = terms_provider
            .lease_terms_for(&gate)
            .await
            .expect_err("unknown capability must fail closed");

        assert!(matches!(
            error,
            ProductWorkflowError::ApprovalInteractionRejected {
                kind: ApprovalInteractionRejectionKind::LeaseTermsUnavailable
            }
        ));
    }
}
