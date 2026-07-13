use std::{collections::HashSet, time::Duration};

use ironclaw_authorization::TrustAwareCapabilityDispatchAuthorizer;
use ironclaw_extensions::{
    CapabilityVisibility, ExtensionPackage, ExtensionRegistry, is_hosted_http_mcp_package,
};
use ironclaw_filesystem::RootFilesystem;
use ironclaw_host_api::{
    CapabilityDescriptor, CapabilityGrant, CapabilityId, Decision, EffectKind, ExecutionContext,
    ResourceEstimate, RuntimeKind, canonical_json_v1, runtime_policy::EffectiveRuntimePolicy,
    sha256_digest_token,
};
use ironclaw_trust::TrustDecision;
use serde_json::{Value, json};

use crate::{
    CapabilitySurfaceVersion, HireScope, HostRuntimeError, HostedMcpSurfaceOverlay,
    VisibleCapabilityRequest, VisibleCapabilitySurface,
    capability_catalog::read_json_ref,
    first_party_tools::{BUILTIN_FIRST_PARTY_PROVIDER, resolve_builtin_input_schema_ref},
    plan_capability,
};

/// Wall-clock budget for the hosted-MCP overlay discovery fan-out on one
/// turn's capability-surface build. Independent of the (much larger)
/// per-transport MCP request timeout: this bounds how long a turn will wait
/// on live discovery before falling back to the static floor. Elapsing this
/// budget is treated exactly like a discovery failure — floor only, not
/// cached, never fails the turn.
const OVERLAY_SURFACE_BUDGET: Duration = Duration::from_secs(3);

const ALL_RUNTIME_KINDS: &[RuntimeKind] = &[
    RuntimeKind::Wasm,
    RuntimeKind::Mcp,
    RuntimeKind::Script,
    RuntimeKind::FirstParty,
    RuntimeKind::System,
];

const ALL_EFFECT_KINDS: &[EffectKind] = &[
    EffectKind::ReadFilesystem,
    EffectKind::WriteFilesystem,
    EffectKind::DeleteFilesystem,
    EffectKind::Network,
    EffectKind::UseSecret,
    EffectKind::ExecuteCode,
    EffectKind::SpawnProcess,
    EffectKind::DispatchCapability,
    EffectKind::ModifyExtension,
    EffectKind::ModifyApproval,
    EffectKind::ModifyBudget,
    EffectKind::ExternalWrite,
    EffectKind::Financial,
];

/// Visibility-only policy applied before authorization estimates are rendered.
///
/// This is a narrowing surface policy, not an authority source. A runtime/effect
/// listed here can still be omitted by missing grants, missing provider trust,
/// denied trust ceilings, or an authorizer denial. A runtime/effect absent here
/// is omitted before the authorizer is consulted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilitySurfacePolicy {
    /// Runtime kinds that may appear on this projection.
    ///
    /// Empty means allow none. Order and duplicates do not affect filtering or
    /// surface-version fingerprinting.
    pub allowed_runtimes: Vec<RuntimeKind>,
    /// Effect ceiling for visible descriptors.
    ///
    /// This is strict subset semantics: every effect declared by a capability
    /// must appear in this list or the capability is omitted. Empty means allow
    /// none. Order and duplicates do not affect filtering or surface-version
    /// fingerprinting.
    pub allowed_effects: Vec<EffectKind>,
    /// Whether capabilities that require approval may be rendered as askable.
    ///
    /// This is informational only. It does not issue approval leases or widen
    /// direct invocation authority.
    pub include_requires_approval: bool,
    /// Maximum visible capabilities returned after filtering, in registry
    /// order. `Some(0)` returns an empty surface without authorizer calls.
    pub max_capabilities: Option<usize>,
}

impl CapabilitySurfacePolicy {
    pub fn allow_all() -> Self {
        Self {
            allowed_runtimes: ALL_RUNTIME_KINDS.to_vec(),
            allowed_effects: ALL_EFFECT_KINDS.to_vec(),
            include_requires_approval: true,
            max_capabilities: None,
        }
    }

    fn allows_runtime(&self, runtime: RuntimeKind) -> bool {
        self.allowed_runtimes.contains(&runtime)
    }

    fn allows_effects(&self, effects: &[EffectKind]) -> bool {
        effects
            .iter()
            .all(|effect| self.allowed_effects.contains(effect))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VisibleCapabilityAccess {
    /// Caller can invoke directly if the same context remains authorized at
    /// invocation time.
    Available,
    /// Capability may be shown as askable, but actual use must still block on
    /// the approval/lease path.
    RequiresApproval,
}

/// Capability metadata safe to render on a model/tool surface.
///
/// This is a visibility affordance, not authority. Direct invocation still
/// re-runs host-owned trust, grants, approvals, obligations, and runtime
/// dispatch checks.
#[derive(Debug, Clone, PartialEq)]
pub struct VisibleCapability {
    /// Redacted declarative capability descriptor from the extension registry.
    pub descriptor: CapabilityDescriptor,
    /// Current visibility status for this context and policy.
    pub access: VisibleCapabilityAccess,
    /// Host-selected estimate used for the visibility authorization check.
    pub estimated_resources: ResourceEstimate,
}

/// Which loop populated a descriptor being run through
/// [`CapabilityCatalog::evaluate_descriptor`] — governs whether a schema
/// resolution failure omits the capability (`Overlay`, untrusted
/// marketplace input) or fails the whole surface build (`Floor`, a host
/// bug: the manifest declaration is supposed to always be present).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DescriptorSource {
    Floor,
    Overlay,
}

pub(crate) struct CapabilityCatalog<'a> {
    registry: &'a ExtensionRegistry,
    authorizer: &'a dyn TrustAwareCapabilityDispatchAuthorizer,
    base_version: &'a CapabilitySurfaceVersion,
    runtime_policy: &'a EffectiveRuntimePolicy,
    filesystem: Option<&'a dyn RootFilesystem>,
    hosted_mcp_overlay: Option<&'a dyn HostedMcpSurfaceOverlay>,
}

impl<'a> CapabilityCatalog<'a> {
    pub(crate) fn new(
        registry: &'a ExtensionRegistry,
        authorizer: &'a dyn TrustAwareCapabilityDispatchAuthorizer,
        base_version: &'a CapabilitySurfaceVersion,
        runtime_policy: &'a EffectiveRuntimePolicy,
    ) -> Self {
        Self {
            registry,
            authorizer,
            base_version,
            runtime_policy,
            filesystem: None,
            hosted_mcp_overlay: None,
        }
    }

    pub(crate) fn with_filesystem(mut self, filesystem: &'a dyn RootFilesystem) -> Self {
        self.filesystem = Some(filesystem);
        self
    }

    pub(crate) fn with_hosted_mcp_overlay(
        mut self,
        overlay: &'a dyn HostedMcpSurfaceOverlay,
    ) -> Self {
        self.hosted_mcp_overlay = Some(overlay);
        self
    }

    pub(crate) async fn visible_capabilities(
        &self,
        request: VisibleCapabilityRequest,
    ) -> Result<VisibleCapabilitySurface, HostRuntimeError> {
        request.context.validate().map_err(|error| {
            HostRuntimeError::invalid_request(format!("invalid execution context: {error}"))
        })?;

        let max_capabilities = request.policy.max_capabilities.unwrap_or(usize::MAX);
        let mut capabilities = Vec::new();
        let mut context = request.context.clone();

        // Static floor: unconditional, always runs first. This publishes the
        // globally-registered capabilities (including host-bundled tools
        // like `marketplace.submit_deliverable`) regardless of caller scope.
        for descriptor in self.registry.capabilities() {
            if capabilities.len() >= max_capabilities {
                break;
            }
            if let Some(visible) = self
                .evaluate_descriptor(descriptor, DescriptorSource::Floor, &mut context, &request)
                .await?
            {
                capabilities.push(visible);
            }
        }

        // Per-user hosted-MCP overlay: gated on both an attached overlay
        // provider AND the turn scope carrying an agent_id (`HireScope`).
        // Absent either, this block is skipped entirely — zero discovery
        // calls, zero caching — which is what makes it safe for
        // buyer/operator/system/cli turns. Overlaid descriptors run through
        // the SAME per-descriptor pipeline as the floor above, and floor
        // entries win any `CapabilityId` collision.
        // F4: which pushed entries came from the overlay, so `surface_version`
        // below can hash them scope-stably instead of folding in
        // discovery-health variance (`access`/presence). Populated only in
        // this block; empty (no special-casing) for a turn with no overlay.
        let mut overlay_capability_ids: HashSet<CapabilityId> = HashSet::new();
        if let (Some(overlay), Some(hire)) = (
            self.hosted_mcp_overlay,
            HireScope::from_scope(&request.context.resource_scope),
        ) && capabilities.len() < max_capabilities
        {
            let seen: HashSet<CapabilityId> = capabilities
                .iter()
                .map(|capability| capability.descriptor.id.clone())
                .collect();
            for descriptor in self.discover_overlay_capabilities(overlay, &hire).await {
                if capabilities.len() >= max_capabilities {
                    break;
                }
                if seen.contains(&descriptor.id) {
                    continue;
                }
                let capability_id = descriptor.id.clone();
                if let Some(visible) = self
                    .evaluate_descriptor(
                        &descriptor,
                        DescriptorSource::Overlay,
                        &mut context,
                        &request,
                    )
                    .await?
                {
                    capabilities.push(visible);
                    overlay_capability_ids.insert(capability_id);
                }
            }
        }

        let version = surface_version(
            self.base_version,
            &request,
            self.runtime_policy,
            &capabilities,
            &overlay_capability_ids,
        )?;
        Ok(VisibleCapabilitySurface {
            version,
            capabilities,
        })
    }

    /// Runs one descriptor through the visibility/policy/plan/authorize
    /// pipeline shared by the static floor and the hosted-MCP overlay.
    /// `Ok(None)` means "not visible under this request" (filtered, denied,
    /// or requires approval without that being allowed) — never an error.
    async fn evaluate_descriptor(
        &self,
        descriptor: &CapabilityDescriptor,
        source: DescriptorSource,
        context: &mut ExecutionContext,
        request: &VisibleCapabilityRequest,
    ) -> Result<Option<VisibleCapability>, HostRuntimeError> {
        if !self.is_model_visible(descriptor)
            || !request.policy.allows_runtime(descriptor.runtime)
            || !request.policy.allows_effects(&descriptor.effects)
        {
            return Ok(None);
        }
        if plan_capability(descriptor, self.runtime_policy).is_err() {
            return Ok(None);
        }
        let Some(trust_decision) = request.provider_trust.get(&descriptor.provider) else {
            return Ok(None);
        };
        let estimate = descriptor
            .resource_profile
            .as_ref()
            .map(|profile| profile.default_estimate.clone())
            .unwrap_or_default();
        context.trust = trust_decision.effective_trust.class();

        let access = match self
            .authorizer
            .authorize_dispatch_with_trust(context, descriptor, &estimate, trust_decision)
            .await
        {
            Decision::Allow { .. } => VisibleCapabilityAccess::Available,
            // A discovered hosted-MCP capability reaches `Allow` here (and
            // then `RequireApproval` below via the profile approval gate,
            // since it carries `default_permission = Ask` by construction —
            // `ironclaw_extensions::hosted_mcp_discovery`) IFF composition's
            // `DiscoveredCapabilityGrantSource` minted a real ambient grant
            // for it into `context.grants` before this call. Askable is
            // therefore truthful by construction from ONE source (the
            // ambient grant) rather than a second overlay-only fail-safe
            // arm: a discovered capability with no ambient grant hits
            // `Deny { MissingGrant }` below and drops — visible iff
            // invocable-after-approval, never a phantom askable affordance.
            Decision::RequireApproval { .. } if request.policy.include_requires_approval => {
                VisibleCapabilityAccess::RequiresApproval
            }
            Decision::RequireApproval { .. } | Decision::Deny { .. } => return Ok(None),
        };

        let descriptor = match self.surface_descriptor(descriptor).await {
            Ok(descriptor) => descriptor,
            // An overlay-sourced descriptor is untrusted marketplace input:
            // a discovered capability id is never in the static manifest, so
            // any schema-resolution failure here (including a root-level
            // `$ref` a hosted MCP server should never send, per the trait's
            // inline-schema contract) omits just this one malformed
            // capability instead of failing the whole surface build. A
            // floor descriptor's resolution failure is a genuine host bug
            // and still propagates as `Err` below.
            Err(error) if source == DescriptorSource::Overlay => {
                tracing::debug!(
                    capability_id = %descriptor.id,
                    error = %error,
                    "omitting malformed hosted-MCP overlay capability from the surface"
                );
                return Ok(None);
            }
            Err(error) => return Err(error),
        };

        Ok(Some(VisibleCapability {
            descriptor,
            access,
            estimated_resources: estimate,
        }))
    }

    /// Fetches the per-hire hosted-MCP capability surface across every
    /// hosted-http-mcp package in the registry. Thin wrapper over
    /// [`discover_overlay_capabilities_for_hire`] using this catalog's own
    /// registry — see that function for the fan-out/budget/fail-safe shape.
    async fn discover_overlay_capabilities(
        &self,
        overlay: &dyn HostedMcpSurfaceOverlay,
        hire: &HireScope,
    ) -> Vec<CapabilityDescriptor> {
        discover_overlay_capabilities_for_hire(self.registry, overlay, hire).await
    }

    fn is_model_visible(&self, descriptor: &CapabilityDescriptor) -> bool {
        self.registry
            .capability_visibility(&descriptor.id)
            .unwrap_or(CapabilityVisibility::Model)
            == CapabilityVisibility::Model
    }

    async fn surface_descriptor(
        &self,
        descriptor: &CapabilityDescriptor,
    ) -> Result<CapabilityDescriptor, HostRuntimeError> {
        let mut descriptor = descriptor.clone();
        let reference = descriptor
            .parameters_schema
            .get("$ref")
            .and_then(Value::as_str)
            .map(str::to_string);

        if descriptor.provider.as_str() == BUILTIN_FIRST_PARTY_PROVIDER {
            let Some(reference) = reference else {
                return Err(HostRuntimeError::invalid_request(format!(
                    "built-in capability {} must publish from an input schema ref",
                    descriptor.id
                )));
            };
            descriptor.parameters_schema = resolve_builtin_input_schema_ref(&reference)
                .ok_or_else(|| {
                    HostRuntimeError::invalid_request(format!(
                        "built-in capability {} references unknown input schema {}",
                        descriptor.id, reference
                    ))
                })?;
            return Ok(descriptor);
        }

        let Some(reference) = reference else {
            return Ok(descriptor);
        };
        let Some(filesystem) = self.filesystem else {
            return Ok(descriptor);
        };
        let Some(package) = self.registry.get_extension(&descriptor.provider) else {
            return Ok(descriptor);
        };
        descriptor.parameters_schema =
            resolve_package_input_schema_ref(filesystem, package, &descriptor.id, &reference)
                .await?;
        Ok(descriptor)
    }
}

/// Fetches the per-hire hosted-MCP capability surface across every
/// hosted-http-mcp package in `registry`, budget-bounded and run
/// concurrently. Failure, an empty result, or the budget elapsing all
/// resolve to an empty `Vec` — the caller then serves the static floor
/// only, and (by construction, since nothing here writes state) nothing is
/// cached and the turn never fails.
///
/// Shared between [`CapabilityCatalog::visible_capabilities`] (this file)
/// and `ironclaw_reborn_composition`'s `DiscoveredCapabilityGrantSource`
/// (which needs the SAME per-hire discovered descriptors to mint ambient
/// grants before the surface authorizer runs) and
/// `ironclaw_host_runtime::production::resolve_invocation_registry` (which
/// needs them to merge a discovered descriptor into a per-request registry
/// at invoke/resume time) — one discovery call shape, three consumers, so a
/// future change to the fan-out/budget/error-handling can't drift between
/// them.
pub async fn discover_overlay_capabilities_for_hire(
    registry: &ExtensionRegistry,
    overlay: &dyn HostedMcpSurfaceOverlay,
    hire: &HireScope,
) -> Vec<CapabilityDescriptor> {
    let packages: Vec<&ExtensionPackage> = registry
        .extensions()
        .filter(|package| is_hosted_http_mcp_package(package))
        .collect();
    if packages.is_empty() {
        return Vec::new();
    }

    let fanout = futures_util::future::join_all(
        packages
            .iter()
            .map(|package| overlay.overlay_capabilities(hire, package)),
    );
    match tokio::time::timeout(OVERLAY_SURFACE_BUDGET, fanout).await {
        Ok(results) => results
            .into_iter()
            .zip(packages.iter())
            .flat_map(|(result, package)| match result {
                Ok(descriptors) => descriptors,
                Err(error) => {
                    tracing::debug!(
                        extension_id = %package.id,
                        error = ?error,
                        "hosted MCP overlay discovery failed; serving static floor only"
                    );
                    Vec::new()
                }
            })
            .collect(),
        Err(_) => {
            tracing::debug!(
                budget_secs = OVERLAY_SURFACE_BUDGET.as_secs(),
                "hosted MCP overlay discovery exceeded budget; serving static floor only"
            );
            Vec::new()
        }
    }
}

async fn resolve_package_input_schema_ref(
    filesystem: &dyn RootFilesystem,
    package: &ExtensionPackage,
    capability_id: &ironclaw_host_api::CapabilityId,
    reference: &str,
) -> Result<Value, HostRuntimeError> {
    let Some(declaration) = package
        .manifest
        .capabilities
        .iter()
        .find(|capability| &capability.id == capability_id)
    else {
        return Err(HostRuntimeError::invalid_request(format!(
            "capability {capability_id} is missing manifest declaration"
        )));
    };
    if declaration.input_schema_ref.as_str() != reference {
        return Err(HostRuntimeError::invalid_request(format!(
            "capability {capability_id} descriptor schema ref {reference} does not match manifest input schema ref {}",
            declaration.input_schema_ref.as_str()
        )));
    }
    read_json_ref(
        filesystem,
        &package.root,
        &declaration.input_schema_ref,
        "input_schema_ref",
    )
    .await
}

fn surface_version(
    base_version: &CapabilitySurfaceVersion,
    request: &VisibleCapabilityRequest,
    runtime_policy: &EffectiveRuntimePolicy,
    capabilities: &[VisibleCapability],
    overlay_capability_ids: &HashSet<CapabilityId>,
) -> Result<CapabilitySurfaceVersion, HostRuntimeError> {
    let context_payload = context_version_payload(request)?;
    // F4: overlay-sourced entries are excluded from the version hash
    // entirely — not merely reduced to their id — because their SET
    // (which discovered ids happen to be present right now) is exactly
    // the discovery-health-dependent state that must NOT flip the surface
    // version between an approval gate raise and its later resume. The
    // per-id presence check in
    // `ironclaw_agent_loop::executor::capability_helpers::capability_is_visible`
    // against the CURRENT surface remains the real "is this specific tool
    // still there" authority; a genuinely revoked/removed discovered
    // capability still fails that check and drops (fail-closed unchanged).
    let mut capability_payload = capabilities
        .iter()
        .filter(|capability| !overlay_capability_ids.contains(&capability.descriptor.id))
        .map(|capability| {
            let descriptor = canonical_descriptor_for_version(&capability.descriptor);
            let trust = request
                .provider_trust
                .get(&capability.descriptor.provider)
                .map(trust_decision_version_payload);
            (
                capability_version_key(capability),
                json!({
                    "descriptor": descriptor,
                    "estimated_resources": &capability.estimated_resources,
                    "access": access_token(capability.access),
                    "provider_trust": trust,
                }),
            )
        })
        .collect::<Vec<_>>();
    capability_payload.sort_by(|(left, _), (right, _)| left.cmp(right));
    let capability_payload = capability_payload
        .into_iter()
        .map(|(_, payload)| payload)
        .collect::<Vec<_>>();
    let payload = json!({
        "version": 1,
        "kind": "visible_capability_surface",
        "base_version": base_version.as_str(),
        "surface_kind": request.surface_kind.as_str(),
        "context": context_payload,
        "policy": {
            "allowed_runtimes": canonical_runtime_kinds(&request.policy.allowed_runtimes),
            "allowed_effects": canonical_effect_kinds(&request.policy.allowed_effects),
            "include_requires_approval": request.policy.include_requires_approval,
            "max_capabilities": request.policy.max_capabilities,
        },
        "runtime_policy": runtime_policy,
        "capabilities": capability_payload,
    });
    let canonical = canonical_json_v1(&payload).map_err(host_api_error)?;
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| HostRuntimeError::invalid_request(error.to_string()))?;
    CapabilitySurfaceVersion::new(sha256_digest_token(&bytes))
}

fn context_version_payload(request: &VisibleCapabilityRequest) -> Result<Value, HostRuntimeError> {
    let context = &request.context;
    Ok(json!({
        "tenant_id": &context.tenant_id,
        "user_id": &context.user_id,
        "agent_id": &context.agent_id,
        "project_id": &context.project_id,
        "mission_id": &context.mission_id,
        "thread_id": &context.thread_id,
        "extension_id": &context.extension_id,
        "runtime": context.runtime,
        "grants": canonical_grants(&context.grants.grants)?,
    }))
}

fn canonical_grants(grants: &[CapabilityGrant]) -> Result<Vec<Value>, HostRuntimeError> {
    let mut payload = grants
        .iter()
        .map(|grant| {
            let value = json!({
                "capability": &grant.capability,
                "grantee": &grant.grantee,
                "allowed_effects": canonical_effect_kinds(&grant.constraints.allowed_effects),
                "resource_ceiling": &grant.constraints.resource_ceiling,
                "expires_at": &grant.constraints.expires_at,
                "max_invocations": grant.constraints.max_invocations,
                "secret_count": grant.constraints.secrets.len(),
            });
            let canonical = canonical_json_v1(&value).map_err(host_api_error)?;
            let key = stable_json_string(&canonical)?;
            Ok((key, canonical))
        })
        .collect::<Result<Vec<_>, HostRuntimeError>>()?;
    payload.sort_by(|(left, _), (right, _)| left.cmp(right));
    Ok(payload.into_iter().map(|(_, value)| value).collect())
}

fn trust_decision_version_payload(trust_decision: &TrustDecision) -> Value {
    json!({
        "effective_trust": &trust_decision.effective_trust,
        "authority_ceiling": {
            "allowed_effects": canonical_effect_kinds(&trust_decision.authority_ceiling.allowed_effects),
            "max_resource_ceiling": &trust_decision.authority_ceiling.max_resource_ceiling,
        },
    })
}

fn canonical_descriptor_for_version(descriptor: &CapabilityDescriptor) -> CapabilityDescriptor {
    let mut descriptor = descriptor.clone();
    descriptor
        .effects
        .sort_by_key(|effect| effect_kind_token(*effect));
    descriptor.effects.dedup();
    descriptor
}

fn capability_version_key(
    capability: &VisibleCapability,
) -> (String, String, &'static str, &'static str) {
    (
        capability.descriptor.id.as_str().to_string(),
        capability.descriptor.provider.as_str().to_string(),
        runtime_kind_token(capability.descriptor.runtime),
        access_token(capability.access),
    )
}

fn canonical_runtime_kinds(runtimes: &[RuntimeKind]) -> Vec<&'static str> {
    let mut values = runtimes
        .iter()
        .map(|runtime| runtime_kind_token(*runtime))
        .collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    values
}

fn canonical_effect_kinds(effects: &[EffectKind]) -> Vec<&'static str> {
    let mut values = effects
        .iter()
        .map(|effect| effect_kind_token(*effect))
        .collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    values
}

fn runtime_kind_token(runtime: RuntimeKind) -> &'static str {
    match runtime {
        RuntimeKind::Wasm => "wasm",
        RuntimeKind::Mcp => "mcp",
        RuntimeKind::Script => "script",
        RuntimeKind::FirstParty => "first_party",
        RuntimeKind::System => "system",
    }
}

fn effect_kind_token(effect: EffectKind) -> &'static str {
    match effect {
        EffectKind::ReadFilesystem => "read_filesystem",
        EffectKind::WriteFilesystem => "write_filesystem",
        EffectKind::DeleteFilesystem => "delete_filesystem",
        EffectKind::Network => "network",
        EffectKind::UseSecret => "use_secret",
        EffectKind::ExecuteCode => "execute_code",
        EffectKind::SpawnProcess => "spawn_process",
        EffectKind::DispatchCapability => "dispatch_capability",
        EffectKind::ModifyExtension => "modify_extension",
        EffectKind::ModifyApproval => "modify_approval",
        EffectKind::ModifyBudget => "modify_budget",
        EffectKind::ExternalWrite => "external_write",
        EffectKind::Financial => "financial",
    }
}

fn access_token(access: VisibleCapabilityAccess) -> &'static str {
    match access {
        VisibleCapabilityAccess::Available => "available",
        VisibleCapabilityAccess::RequiresApproval => "requires_approval",
    }
}

fn stable_json_string(value: &Value) -> Result<String, HostRuntimeError> {
    serde_json::to_string(value)
        .map_err(|error| HostRuntimeError::invalid_request(error.to_string()))
}

fn host_api_error(error: ironclaw_host_api::HostApiError) -> HostRuntimeError {
    HostRuntimeError::invalid_request(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironclaw_authorization::GrantAuthorizer;
    use ironclaw_host_api::{
        CapabilityId, DenyReason, ExtensionId, PermissionMode, TrustClass,
        runtime_policy::{
            ApprovalPolicy, AuditMode, DeploymentMode, EffectiveRuntimePolicy,
            FilesystemBackendKind, NetworkMode, ProcessBackendKind, RuntimeProfile, SecretMode,
        },
    };

    fn test_runtime_policy() -> EffectiveRuntimePolicy {
        EffectiveRuntimePolicy {
            deployment: DeploymentMode::LocalSingleUser,
            requested_profile: RuntimeProfile::SecureDefault,
            resolved_profile: RuntimeProfile::SecureDefault,
            filesystem_backend: FilesystemBackendKind::ScopedVirtual,
            process_backend: ProcessBackendKind::None,
            network_mode: NetworkMode::Deny,
            secret_mode: SecretMode::Deny,
            approval_policy: ApprovalPolicy::AskAlways,
            audit_mode: AuditMode::LocalMinimal,
        }
    }

    #[tokio::test]
    async fn builtin_surface_descriptor_requires_input_schema_ref() {
        let descriptor = CapabilityDescriptor {
            id: CapabilityId::new("builtin.bad").unwrap(),
            provider: ExtensionId::new(BUILTIN_FIRST_PARTY_PROVIDER).unwrap(),
            runtime: RuntimeKind::FirstParty,
            trust_ceiling: TrustClass::UserTrusted,
            description: "bad built-in descriptor".to_string(),
            parameters_schema: json!({"type": "object"}),
            effects: vec![EffectKind::DispatchCapability],
            default_permission: PermissionMode::Allow,
            runtime_credentials: Vec::new(),
            resource_profile: None,
        };
        let registry = ExtensionRegistry::new();
        let runtime_policy = test_runtime_policy();
        let surface_version = CapabilitySurfaceVersion::new("surface-v1").unwrap();
        let authorizer = GrantAuthorizer;
        let catalog =
            CapabilityCatalog::new(&registry, &authorizer, &surface_version, &runtime_policy);

        let error = catalog
            .surface_descriptor(&descriptor)
            .await
            .expect_err("built-in schema refs are required");

        assert!(
            matches!(error, HostRuntimeError::InvalidRequest { ref reason }
                if reason.contains("must publish from an input schema ref")),
            "unexpected error: {error:?}"
        );
    }

    // ---- hosted-MCP overlay union/gate regression coverage ----
    //
    // These drive `CapabilityCatalog::visible_capabilities` directly, which
    // is the entire body of `DefaultHostRuntime::visible_capabilities`
    // (production.rs:1050) — there is no branching logic between the two, so
    // this is "through the real caller" for the merge/gate/dedup/budget
    // behavior under test. Multi-tenant isolation and the composition-owned
    // cache/single-flight behavior are covered separately in
    // `ironclaw_reborn_composition::extension_host::hosted_mcp_overlay`
    // against the real fake egress.

    use crate::{HostedMcpOverlayError, SurfaceKind};
    use ironclaw_host_api::{AgentId, Obligations, ProjectId, TenantId, UserId};
    use ironclaw_trust::{AuthorityCeiling, EffectiveTrustClass, TrustDecision, TrustProvenance};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct AllowAllAuthorizer;

    #[async_trait::async_trait]
    impl TrustAwareCapabilityDispatchAuthorizer for AllowAllAuthorizer {
        async fn authorize_dispatch_with_trust(
            &self,
            _context: &ExecutionContext,
            _descriptor: &CapabilityDescriptor,
            _estimate: &ResourceEstimate,
            _trust_decision: &TrustDecision,
        ) -> Decision {
            Decision::Allow {
                obligations: Obligations::default(),
            }
        }
    }

    /// Authorizer that mirrors production `GrantAuthorizer` for this test:
    /// capabilities with a pre-provisioned grant authorize (`Allow`); any other
    /// id — e.g. a freshly discovered overlay capability — has no grant and is
    /// denied with `MissingGrant`, exactly as the live grant authorizer does.
    struct GrantGatedAuthorizer {
        granted: Vec<CapabilityId>,
    }

    #[async_trait::async_trait]
    impl TrustAwareCapabilityDispatchAuthorizer for GrantGatedAuthorizer {
        async fn authorize_dispatch_with_trust(
            &self,
            _context: &ExecutionContext,
            descriptor: &CapabilityDescriptor,
            _estimate: &ResourceEstimate,
            _trust_decision: &TrustDecision,
        ) -> Decision {
            if self.granted.contains(&descriptor.id) {
                Decision::Allow {
                    obligations: Obligations::default(),
                }
            } else {
                Decision::Deny {
                    reason: DenyReason::MissingGrant,
                }
            }
        }
    }

    struct NeverCalledOverlay {
        calls: AtomicUsize,
    }

    impl NeverCalledOverlay {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl HostedMcpSurfaceOverlay for NeverCalledOverlay {
        async fn overlay_capabilities(
            &self,
            _hire: &HireScope,
            _package: &ExtensionPackage,
        ) -> Result<Vec<CapabilityDescriptor>, HostedMcpOverlayError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
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

    struct FailingOverlay;

    #[async_trait::async_trait]
    impl HostedMcpSurfaceOverlay for FailingOverlay {
        async fn overlay_capabilities(
            &self,
            _hire: &HireScope,
            _package: &ExtensionPackage,
        ) -> Result<Vec<CapabilityDescriptor>, HostedMcpOverlayError> {
            Err(HostedMcpOverlayError::Transient(
                "simulated backend failure".to_string(),
            ))
        }
    }

    struct SlowOverlay;

    #[async_trait::async_trait]
    impl HostedMcpSurfaceOverlay for SlowOverlay {
        async fn overlay_capabilities(
            &self,
            _hire: &HireScope,
            _package: &ExtensionPackage,
        ) -> Result<Vec<CapabilityDescriptor>, HostedMcpOverlayError> {
            tokio::time::sleep(OVERLAY_SURFACE_BUDGET * 10).await;
            Ok(Vec::new())
        }
    }

    /// Registers one hosted-http-mcp package (`notion`) with a single
    /// manifest-declared floor capability `notion.notion-fetch`, so both the
    /// static-floor loop and the overlay's package fan-out have something to
    /// act on.
    fn registry_with_hosted_mcp_floor() -> ExtensionRegistry {
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
        .expect("valid manifest");
        let package = ExtensionPackage::from_manifest(
            manifest,
            ironclaw_host_api::VirtualPath::new("/system/extensions/notion").expect("valid root"),
        )
        .expect("valid package");
        let mut registry = ExtensionRegistry::new();
        registry.insert(package).expect("insert notion package");
        registry
    }

    fn overlay_capability_descriptor(id: &str, description: &str) -> CapabilityDescriptor {
        CapabilityDescriptor {
            id: CapabilityId::new(id).unwrap(),
            provider: ExtensionId::new("notion").unwrap(),
            runtime: RuntimeKind::Mcp,
            trust_ceiling: TrustClass::UserTrusted,
            description: description.to_string(),
            parameters_schema: json!({"type": "object"}),
            effects: vec![EffectKind::DispatchCapability, EffectKind::Network],
            default_permission: PermissionMode::Ask,
            runtime_credentials: Vec::new(),
            resource_profile: None,
        }
    }

    fn overlay_test_runtime_policy() -> EffectiveRuntimePolicy {
        EffectiveRuntimePolicy {
            deployment: DeploymentMode::LocalSingleUser,
            requested_profile: RuntimeProfile::SecureDefault,
            resolved_profile: RuntimeProfile::SecureDefault,
            filesystem_backend: FilesystemBackendKind::ScopedVirtual,
            process_backend: ProcessBackendKind::None,
            network_mode: NetworkMode::Brokered,
            secret_mode: SecretMode::BrokeredHandles,
            approval_policy: ApprovalPolicy::AskAlways,
            audit_mode: AuditMode::LocalMinimal,
        }
    }

    fn overlay_request(agent_id: Option<&str>) -> VisibleCapabilityRequest {
        let user_id = UserId::new("buyer-1").unwrap();
        let mut context = ExecutionContext::local_default(
            user_id.clone(),
            ExtensionId::new("notion").unwrap(),
            RuntimeKind::Mcp,
            TrustClass::UserTrusted,
            Default::default(),
            Default::default(),
        )
        .unwrap();
        let tenant_id = TenantId::new("acme").unwrap();
        let agent_id = agent_id.map(|id| AgentId::new(id).unwrap());
        let project_id = Some(ProjectId::new("proj-1").unwrap());
        context.tenant_id = tenant_id.clone();
        context.agent_id = agent_id.clone();
        context.project_id = project_id.clone();
        context.resource_scope.tenant_id = tenant_id;
        context.resource_scope.agent_id = agent_id;
        context.resource_scope.project_id = project_id;
        context.validate().expect("valid execution context");

        let mut provider_trust = std::collections::BTreeMap::new();
        provider_trust.insert(
            ExtensionId::new("notion").unwrap(),
            TrustDecision {
                effective_trust: EffectiveTrustClass::user_trusted(),
                authority_ceiling: AuthorityCeiling {
                    allowed_effects: ALL_EFFECT_KINDS.to_vec(),
                    max_resource_ceiling: None,
                },
                provenance: TrustProvenance::AdminConfig,
                evaluated_at: chrono::Utc::now(),
            },
        );

        VisibleCapabilityRequest::new(context, SurfaceKind::new("test").unwrap())
            .with_policy(CapabilitySurfacePolicy::allow_all())
            .with_provider_trust(provider_trust)
    }

    #[tokio::test]
    async fn visible_capabilities_none_agent_turn_serves_floor_only_and_never_calls_overlay() {
        let registry = registry_with_hosted_mcp_floor();
        let runtime_policy = overlay_test_runtime_policy();
        let surface_version = CapabilitySurfaceVersion::new("surface-v1").unwrap();
        let authorizer = AllowAllAuthorizer;
        let overlay = NeverCalledOverlay::new();
        let catalog =
            CapabilityCatalog::new(&registry, &authorizer, &surface_version, &runtime_policy)
                .with_hosted_mcp_overlay(&overlay);

        let surface = catalog
            .visible_capabilities(overlay_request(None))
            .await
            .expect("floor-only surface succeeds");

        assert_eq!(surface.capabilities.len(), 1);
        assert_eq!(
            surface.capabilities[0].descriptor.id.as_str(),
            "notion.notion-fetch"
        );
        assert_eq!(
            overlay.calls.load(Ordering::SeqCst),
            0,
            "a None-agent turn must never call hosted-MCP discovery"
        );
    }

    #[tokio::test]
    async fn visible_capabilities_unions_overlay_with_floor_and_floor_wins_id_collisions() {
        let registry = registry_with_hosted_mcp_floor();
        let runtime_policy = overlay_test_runtime_policy();
        let surface_version = CapabilitySurfaceVersion::new("surface-v1").unwrap();
        let authorizer = AllowAllAuthorizer;
        let overlay = StaticOverlay {
            descriptors: vec![
                // Colliding id: floor must win, this description must not surface.
                overlay_capability_descriptor("notion.notion-fetch", "overlay collision"),
                overlay_capability_descriptor("notion.live-search", "discovered tool"),
            ],
        };
        let catalog =
            CapabilityCatalog::new(&registry, &authorizer, &surface_version, &runtime_policy)
                .with_hosted_mcp_overlay(&overlay);

        let surface = catalog
            .visible_capabilities(overlay_request(Some("agent-1")))
            .await
            .expect("union surface succeeds");

        assert_eq!(
            surface.capabilities.len(),
            2,
            "floor + one new overlay capability"
        );
        let fetch = surface
            .capabilities
            .iter()
            .find(|capability| capability.descriptor.id.as_str() == "notion.notion-fetch")
            .expect("floor capability present");
        assert_eq!(
            fetch.descriptor.description, "floor capability",
            "floor descriptor must win the id collision, not the overlay's"
        );
        assert!(
            surface
                .capabilities
                .iter()
                .any(|capability| capability.descriptor.id.as_str() == "notion.live-search"),
            "new overlay capability must be surfaced"
        );
    }

    #[tokio::test]
    async fn visible_capabilities_drops_ungranted_discovered_tool_instead_of_a_phantom_askable_entry()
     {
        // S2 regression (supersedes the deleted overlay-only MissingGrant
        // fail-safe arm): a discovered tool with NO real ambient grant must
        // NOT surface as askable. Before S2, `evaluate_descriptor` special-
        // cased `Deny{MissingGrant}` for overlay-sourced descriptors into
        // `RequiresApproval` — visible-but-uninvocable, since nothing had
        // minted a matching grant, so an "approved" call on it would still
        // hard-deny at invoke (`AuthorizationDenied`) instead of proceeding.
        // Deleting that arm makes askable IFF a real ambient grant exists —
        // the discovered tool now drops (fail-closed) exactly like an
        // ungranted floor capability, closing the phantom-affordance gap.
        let registry = registry_with_hosted_mcp_floor();
        let runtime_policy = overlay_test_runtime_policy();
        let surface_version = CapabilitySurfaceVersion::new("surface-v1").unwrap();
        // Floor capability granted; the discovered `notion.live-search` is
        // not — no `DiscoveredCapabilityGrantSource` grant was minted into
        // this context, matching a real turn where discovery surfaced a
        // tool the hire was never actually granted.
        let authorizer = GrantGatedAuthorizer {
            granted: vec![CapabilityId::new("notion.notion-fetch").unwrap()],
        };
        let overlay = StaticOverlay {
            descriptors: vec![overlay_capability_descriptor(
                "notion.live-search",
                "discovered tool",
            )],
        };
        let catalog =
            CapabilityCatalog::new(&registry, &authorizer, &surface_version, &runtime_policy)
                .with_hosted_mcp_overlay(&overlay);

        let surface = catalog
            .visible_capabilities(overlay_request(Some("agent-1")))
            .await
            .expect("union surface succeeds");

        assert_eq!(
            surface.capabilities.len(),
            1,
            "only the granted floor tool surfaces; the ungranted discovered tool drops"
        );
        assert!(
            surface
                .capabilities
                .iter()
                .all(|capability| capability.descriptor.id.as_str() != "notion.live-search"),
            "an ungranted discovered tool must not appear as a phantom askable entry"
        );
    }

    #[tokio::test]
    async fn surface_version_is_stable_across_an_overlay_discovery_health_flip() {
        // F4 regression: `surface_version` must not fold overlay-discovered
        // content into its hash, because a fixed scope's discovered set
        // legitimately varies with live discovery health (a transient
        // outage, a TTL-cache miss, a marketplace revocation not yet
        // reflected). Before the fix, an approval gate raised while the
        // discovered tool was present would silently no-op at resume if
        // discovery returned something different (or nothing) moments
        // later, because `capability_is_visible`'s
        // `call.surface_version != surface.version` check would fire on the
        // unrelated overlay-set change. The per-id presence check downstream
        // remains the real "is this tool still there" authority — this test
        // only pins that the version itself is scope-stable.
        let registry = registry_with_hosted_mcp_floor();
        let runtime_policy = overlay_test_runtime_policy();
        let surface_version = CapabilitySurfaceVersion::new("surface-v1").unwrap();
        let authorizer = AllowAllAuthorizer;

        let healthy_overlay = StaticOverlay {
            descriptors: vec![overlay_capability_descriptor(
                "notion.live-search",
                "discovered tool",
            )],
        };
        let healthy_catalog =
            CapabilityCatalog::new(&registry, &authorizer, &surface_version, &runtime_policy)
                .with_hosted_mcp_overlay(&healthy_overlay);
        let healthy_surface = healthy_catalog
            .visible_capabilities(overlay_request(Some("agent-1")))
            .await
            .expect("healthy discovery surface succeeds");
        assert_eq!(healthy_surface.capabilities.len(), 2);

        // Simulates a discovery-health flip: a DIFFERENT set of discovered
        // tools (here: none at all, the discovery-failure/timeout shape) for
        // the exact same scope/policy/floor.
        let degraded_overlay = StaticOverlay {
            descriptors: Vec::new(),
        };
        let degraded_catalog =
            CapabilityCatalog::new(&registry, &authorizer, &surface_version, &runtime_policy)
                .with_hosted_mcp_overlay(&degraded_overlay);
        let degraded_surface = degraded_catalog
            .visible_capabilities(overlay_request(Some("agent-1")))
            .await
            .expect("degraded discovery surface succeeds");
        assert_eq!(degraded_surface.capabilities.len(), 1);

        assert_eq!(
            healthy_surface.version, degraded_surface.version,
            "surface_version must not flip when only the overlay-discovered \
             set changes for an unchanged floor/context/policy"
        );
    }

    #[tokio::test]
    async fn visible_capabilities_still_drops_ungranted_floor_capability() {
        // The MissingGrant->requires-approval affordance is overlay-only: a
        // floor capability the authorizer denies for MissingGrant still drops,
        // so the fix cannot widen the static floor surface.
        let registry = registry_with_hosted_mcp_floor();
        let runtime_policy = overlay_test_runtime_policy();
        let surface_version = CapabilitySurfaceVersion::new("surface-v1").unwrap();
        let authorizer = GrantGatedAuthorizer {
            granted: Vec::new(),
        };
        let overlay = NeverCalledOverlay::new();
        let catalog =
            CapabilityCatalog::new(&registry, &authorizer, &surface_version, &runtime_policy)
                .with_hosted_mcp_overlay(&overlay);

        let surface = catalog
            .visible_capabilities(overlay_request(Some("agent-1")))
            .await
            .expect("surface builds");

        assert!(
            surface.capabilities.is_empty(),
            "an ungranted floor capability must not surface via the overlay affordance"
        );
    }

    #[tokio::test]
    async fn visible_capabilities_falls_back_to_floor_when_overlay_discovery_fails() {
        let registry = registry_with_hosted_mcp_floor();
        let runtime_policy = overlay_test_runtime_policy();
        let surface_version = CapabilitySurfaceVersion::new("surface-v1").unwrap();
        let authorizer = AllowAllAuthorizer;
        let overlay = FailingOverlay;
        let catalog =
            CapabilityCatalog::new(&registry, &authorizer, &surface_version, &runtime_policy)
                .with_hosted_mcp_overlay(&overlay);

        let surface = catalog
            .visible_capabilities(overlay_request(Some("agent-1")))
            .await
            .expect("discovery failure must not fail the turn");

        assert_eq!(surface.capabilities.len(), 1);
        assert_eq!(
            surface.capabilities[0].descriptor.id.as_str(),
            "notion.notion-fetch"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn visible_capabilities_falls_back_to_floor_when_overlay_discovery_exceeds_budget() {
        let registry = registry_with_hosted_mcp_floor();
        let runtime_policy = overlay_test_runtime_policy();
        let surface_version = CapabilitySurfaceVersion::new("surface-v1").unwrap();
        let authorizer = AllowAllAuthorizer;
        let overlay = SlowOverlay;
        let catalog =
            CapabilityCatalog::new(&registry, &authorizer, &surface_version, &runtime_policy)
                .with_hosted_mcp_overlay(&overlay);

        let surface = catalog
            .visible_capabilities(overlay_request(Some("agent-1")))
            .await
            .expect("budget timeout must not fail the turn");

        assert_eq!(surface.capabilities.len(), 1);
        assert_eq!(
            surface.capabilities[0].descriptor.id.as_str(),
            "notion.notion-fetch"
        );
    }

    #[tokio::test]
    async fn visible_capabilities_omits_overlay_when_no_overlay_is_attached() {
        // Absent-overlay path (e.g. minimal/test host runtimes that never
        // attach one): must behave exactly like the pre-overlay code path.
        let registry = registry_with_hosted_mcp_floor();
        let runtime_policy = overlay_test_runtime_policy();
        let surface_version = CapabilitySurfaceVersion::new("surface-v1").unwrap();
        let authorizer = AllowAllAuthorizer;
        let catalog =
            CapabilityCatalog::new(&registry, &authorizer, &surface_version, &runtime_policy);

        let surface = catalog
            .visible_capabilities(overlay_request(Some("agent-1")))
            .await
            .expect("no-overlay surface succeeds");

        assert_eq!(surface.capabilities.len(), 1);
    }

    #[tokio::test]
    async fn visible_capabilities_omits_overlay_descriptor_with_unresolvable_ref_instead_of_failing_the_turn()
     {
        // F1 regression: a discovered tool is untrusted marketplace input. A
        // root-level `$ref` (valid JSON Schema, but never in the static
        // manifest since discovered capability ids are dynamic) must not
        // terminalize the whole surface build — it must simply be omitted.
        //
        // `with_filesystem` is required to reach the resolution branch at
        // all (unset, a `$ref` descriptor passes through unresolved and the
        // bug is unreachable), which means the FLOOR's own `notion.notion-fetch`
        // descriptor also resolves its `$ref` for real here — so a real file
        // is mounted for it. The overlay's `notion.live-search` id is never
        // in the static manifest, so its resolution fails at the
        // `manifest.capabilities.iter().find(..)` step (before any file
        // read), which is the exact failure this test targets.
        let registry = registry_with_hosted_mcp_floor();
        let runtime_policy = overlay_test_runtime_policy();
        let surface_version = CapabilitySurfaceVersion::new("surface-v1").unwrap();
        let authorizer = AllowAllAuthorizer;

        let host_root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(host_root.path().join("schemas/notion"))
            .expect("create schema dir");
        std::fs::write(
            host_root.path().join("schemas/notion/fetch.input.json"),
            r#"{"type":"object"}"#,
        )
        .expect("write floor schema file");
        let mut filesystem = ironclaw_filesystem::LocalFilesystem::new();
        filesystem
            .mount_local(
                ironclaw_host_api::VirtualPath::new("/system/extensions/notion").unwrap(),
                ironclaw_host_api::HostPath::from_path_buf(host_root.path().to_path_buf()),
            )
            .expect("mount floor schema root");

        let mut malformed = overlay_capability_descriptor("notion.live-search", "discovered tool");
        malformed.parameters_schema =
            json!({"$ref": "schemas/notion/dynamic/live-search.input.v1.json"});
        let overlay = StaticOverlay {
            descriptors: vec![malformed],
        };
        let catalog =
            CapabilityCatalog::new(&registry, &authorizer, &surface_version, &runtime_policy)
                .with_filesystem(&filesystem)
                .with_hosted_mcp_overlay(&overlay);

        let surface = catalog
            .visible_capabilities(overlay_request(Some("agent-1")))
            .await
            .expect("a malformed overlay descriptor must not fail the surface build");

        assert_eq!(
            surface.capabilities.len(),
            1,
            "floor must still be present; the malformed overlay capability is simply omitted"
        );
        assert_eq!(
            surface.capabilities[0].descriptor.id.as_str(),
            "notion.notion-fetch"
        );
    }
}
