use std::sync::Arc;

use ironclaw_extensions::{
    ExtensionPackage, ExtensionRuntime, ManifestSource, SharedExtensionRegistry,
};
use ironclaw_host_api::{
    CapabilityId, ExtensionId, NetworkPolicy, NetworkScheme, NetworkTargetPattern,
    RuntimeCredentialInjection, RuntimeCredentialRequirement, RuntimeCredentialSource,
    RuntimeHttpEgress,
};
use ironclaw_mcp::{
    McpHostHttpClient, McpHostHttpEgressPlan, McpHostHttpEgressPlanRequest,
    McpHostHttpEgressPlanner, McpRuntime, McpRuntimeConfig, McpRuntimeHttpAdapter,
};

pub(crate) const MCP_RESPONSE_BODY_LIMIT: u64 = 2 * 1024 * 1024;
const MCP_NETWORK_EGRESS_LIMIT: u64 = 2 * 1024 * 1024;
const MCP_TIMEOUT_MS: u32 = 60_000;

pub(crate) fn hosted_http_mcp_runtime(
    registry: Arc<SharedExtensionRegistry>,
    runtime_http_egress: Arc<dyn RuntimeHttpEgress>,
) -> McpRuntime<
    McpHostHttpClient<McpRuntimeHttpAdapter<Arc<dyn RuntimeHttpEgress>>, RegistryMcpEgressPlanner>,
> {
    let client = McpHostHttpClient::new(
        McpRuntimeHttpAdapter::new(runtime_http_egress),
        RegistryMcpEgressPlanner::new(registry),
    );
    McpRuntime::new(McpRuntimeConfig::default(), client)
}

#[derive(Debug, Clone)]
pub(crate) struct RegistryMcpEgressPlanner {
    registry: Arc<SharedExtensionRegistry>,
}

impl RegistryMcpEgressPlanner {
    pub(crate) fn new(registry: Arc<SharedExtensionRegistry>) -> Self {
        Self { registry }
    }

    /// Build the staged credential injections for a hosted-MCP `tools/call`.
    ///
    /// The global extension registry is authoritative: when it holds a
    /// provider-matching descriptor for `capability_id`, its
    /// `runtime_credentials` alone decide the injections (unchanged behavior for
    /// registry-published static-floor tools).
    ///
    /// A per-user live-discovered hosted-MCP capability is deliberately absent
    /// from that registry, so the lookup misses and would otherwise yield no
    /// `Authorization` header (marketplace 401). On a registry miss (or a
    /// provider mismatch) this falls back to `request_credentials` — the
    /// host-resolved requirements the dispatcher already threaded onto the
    /// request — applying the same audience filter and injection shape.
    fn credential_injections(
        &self,
        provider: &ExtensionId,
        capability_id: &CapabilityId,
        endpoint: &HostedMcpEndpoint,
        request_credentials: &[RuntimeCredentialRequirement],
    ) -> Vec<RuntimeCredentialInjection> {
        // `.filter(provider match)` intentionally routes a same-id-different-
        // provider registry hit into the request-credential fallback below,
        // same as a genuine miss. This is safe: the actual secret is still
        // gated by the staged-obligation store keyed on scope + capability_id
        // + handle, and `injections_from_requirements` re-applies
        // `endpoint.allows_target` to the fallback credentials, so a mismatch
        // here can only widen which *audience* gets a staged injection
        // attempt, never bypass the staged-obligation credential gate itself.
        if let Some(injections) = self
            .registry
            .snapshot()
            .get_capability(capability_id)
            .filter(|descriptor| &descriptor.provider == provider)
            .map(|descriptor| {
                Self::injections_from_requirements(
                    capability_id,
                    endpoint,
                    &descriptor.runtime_credentials,
                )
            })
        {
            return injections;
        }
        Self::injections_from_requirements(capability_id, endpoint, request_credentials)
    }

    fn injections_from_requirements(
        capability_id: &CapabilityId,
        endpoint: &HostedMcpEndpoint,
        credentials: &[RuntimeCredentialRequirement],
    ) -> Vec<RuntimeCredentialInjection> {
        credentials
            .iter()
            .filter(|credential| endpoint.allows_target(&credential.audience))
            .map(|credential| RuntimeCredentialInjection {
                handle: credential.handle.clone(),
                source: RuntimeCredentialSource::StagedObligation {
                    capability_id: capability_id.clone(),
                },
                target: credential.target.clone(),
                required: credential.required,
            })
            .collect()
    }

    fn provider_endpoint(&self, provider: &ExtensionId) -> Option<HostedMcpEndpoint> {
        let registry = self.registry.snapshot();
        registry
            .get_extension(provider)
            .and_then(hosted_http_mcp_endpoint)
    }
}

impl McpHostHttpEgressPlanner for RegistryMcpEgressPlanner {
    fn plan(&self, request: McpHostHttpEgressPlanRequest<'_>) -> McpHostHttpEgressPlan {
        let Some(endpoint) = self.provider_endpoint(request.provider) else {
            return McpHostHttpEgressPlan::default();
        };
        if !hosted_mcp_url_allowed(request.url, &endpoint) {
            return McpHostHttpEgressPlan::default();
        }
        let credential_injections = self.credential_injections(
            request.provider,
            request.capability_id,
            &endpoint,
            request.runtime_credentials,
        );
        McpHostHttpEgressPlan {
            // Credential-free hosted MCP providers are valid: the manifest may
            // expose a public/unauthenticated server, and host network policy
            // is still enforced below. Missing credentials for providers that
            // should authenticate are a manifest/catalog validation concern,
            // not an egress-planning reason to block the HTTP request.
            // Must match the bundled manifest's network policy
            // (deny_private_ip_ranges: true) or the dispatcher rejects the
            // request.
            network_policy: hosted_mcp_network_policy(&endpoint),
            credential_injections,
            response_body_limit: Some(MCP_RESPONSE_BODY_LIMIT),
            timeout_ms: Some(MCP_TIMEOUT_MS),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostedMcpEndpoint {
    host_pattern: String,
    port: Option<u16>,
    path: String,
}

impl HostedMcpEndpoint {
    fn parse(url: &str) -> Option<Self> {
        let parsed = url::Url::parse(url).ok()?;
        if parsed.scheme() != "https"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return None;
        }
        Some(Self {
            host_pattern: parsed.host_str()?.to_ascii_lowercase(),
            port: parsed.port(),
            path: normalize_mcp_path(parsed.path()),
        })
    }

    fn allows_target(&self, target: &NetworkTargetPattern) -> bool {
        target.scheme == Some(NetworkScheme::Https)
            && target.host_pattern.eq_ignore_ascii_case(&self.host_pattern)
            && target.port == self.port
    }

    fn matches_url(&self, url: &str) -> bool {
        Self::parse(url).is_some_and(|request_endpoint| request_endpoint == *self)
    }
}

pub(crate) fn hosted_http_mcp_endpoint(package: &ExtensionPackage) -> Option<HostedMcpEndpoint> {
    if package.manifest.source != ManifestSource::HostBundled {
        return None;
    }
    let ExtensionRuntime::Mcp {
        transport,
        command: None,
        args,
        url: Some(url),
    } = &package.manifest.runtime
    else {
        return None;
    };
    if transport != "http" || !args.is_empty() {
        return None;
    }
    HostedMcpEndpoint::parse(url)
}

/// Returns `true` only when `url` has scheme `https`, a host that
/// case-insensitively matches `endpoint.host_pattern`, and a path that
/// (ignoring trailing slashes) matches `endpoint.path`.
fn hosted_mcp_url_allowed(url: &str, endpoint: &HostedMcpEndpoint) -> bool {
    endpoint.matches_url(url)
}

fn normalize_mcp_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

fn hosted_mcp_network_policy(endpoint: &HostedMcpEndpoint) -> NetworkPolicy {
    NetworkPolicy {
        allowed_targets: vec![NetworkTargetPattern {
            scheme: Some(NetworkScheme::Https),
            host_pattern: endpoint.host_pattern.clone(),
            port: endpoint.port,
        }],
        // Matches the bundled manifest's deny_private_ip_ranges default.
        // Dispatcher would reject anyway, but the plan must agree.
        deny_private_ip_ranges: true,
        max_egress_bytes: Some(MCP_NETWORK_EGRESS_LIMIT),
    }
}

#[cfg(test)]
mod tests {
    use ironclaw_extensions::{ExtensionManifest, ExtensionPackage, ManifestSource};
    use ironclaw_host_api::{
        CapabilityId, CapabilityProfileSchemaRef, ExtensionId, InvocationId, NetworkMethod,
        NetworkScheme, NetworkTargetPattern, PermissionMode, ProjectId, ResourceScope,
        RuntimeCredentialAccountProviderId, RuntimeCredentialRequirementSource,
        RuntimeCredentialTarget, SecretHandle, TenantId, TrustClass, UserId, VirtualPath,
    };

    use super::*;

    const NOTION_MCP_HOST: &str = "mcp.notion.com";
    const NOTION_MCP_URL: &str = "https://mcp.notion.com/mcp";

    // ── credential projection ──────────────────────────────────────────────

    #[test]
    fn mcp_planner_projects_manifest_runtime_credentials_to_staged_injections() {
        let registry = Arc::new(SharedExtensionRegistry::new(registry_with_notion()));
        let planner = RegistryMcpEgressPlanner::new(registry);
        let provider = ExtensionId::new("notion").unwrap();
        let capability_id = CapabilityId::new("notion.notion-search").unwrap();
        let endpoint = HostedMcpEndpoint::parse(NOTION_MCP_URL).unwrap();

        // Registry hit is authoritative: request-provided credentials are
        // ignored (pass empty) because the registry descriptor supplies them.
        let injections = planner.credential_injections(&provider, &capability_id, &endpoint, &[]);

        assert_eq!(injections.len(), 1);
        assert_eq!(
            injections[0].handle,
            SecretHandle::new("mcp_notion_access_token").unwrap()
        );
        assert_eq!(
            injections[0].source,
            RuntimeCredentialSource::StagedObligation { capability_id }
        );
        assert!(matches!(
            injections[0].target,
            RuntimeCredentialTarget::Header { .. }
        ));
    }

    // ── discovered-capability credential fallback (the "5th gate") ─────────

    /// A per-user live-discovered hosted-MCP capability is deliberately absent
    /// from the global registry. Without the request-credential fallback the
    /// planner emits zero injections and the marketplace `tools/call` egresses
    /// without its `Authorization` header (401 → BlockedAuth). The fallback
    /// must reconstruct the same staged injection discovery already used.
    #[test]
    fn mcp_planner_falls_back_to_request_credentials_when_capability_absent_from_registry() {
        let registry = Arc::new(SharedExtensionRegistry::new(registry_with_notion()));
        let planner = RegistryMcpEgressPlanner::new(registry);
        let provider = ExtensionId::new("notion").unwrap();
        let discovered = CapabilityId::new("notion.echo-broker-test__echo_ping").unwrap();
        let endpoint = HostedMcpEndpoint::parse(NOTION_MCP_URL).unwrap();
        let request_credentials = vec![
            request_credential("mcp_notion_access_token", NOTION_MCP_HOST),
            // Different audience — must be filtered out by `allows_target`.
            request_credential("wrong_audience_token", "other.example.com"),
        ];

        let injections =
            planner.credential_injections(&provider, &discovered, &endpoint, &request_credentials);

        assert_eq!(injections.len(), 1);
        assert_eq!(
            injections[0].handle,
            SecretHandle::new("mcp_notion_access_token").unwrap()
        );
        assert_eq!(
            injections[0].source,
            RuntimeCredentialSource::StagedObligation {
                capability_id: discovered
            }
        );
        assert!(matches!(
            injections[0].target,
            RuntimeCredentialTarget::Header { .. }
        ));
        assert!(injections[0].required);
    }

    /// Registry hit stays authoritative: a request-provided credential for a
    /// registry-published (static-floor) capability is ignored so the fallback
    /// cannot override or shadow the registry descriptor.
    #[test]
    fn mcp_planner_registry_hit_overrides_request_credentials() {
        let registry = Arc::new(SharedExtensionRegistry::new(registry_with_notion()));
        let planner = RegistryMcpEgressPlanner::new(registry);
        let provider = ExtensionId::new("notion").unwrap();
        let registry_cap = CapabilityId::new("notion.notion-search").unwrap();
        let endpoint = HostedMcpEndpoint::parse(NOTION_MCP_URL).unwrap();
        let request_credentials = vec![request_credential("request_only_token", NOTION_MCP_HOST)];

        let injections = planner.credential_injections(
            &provider,
            &registry_cap,
            &endpoint,
            &request_credentials,
        );

        assert_eq!(injections.len(), 1);
        assert_eq!(
            injections[0].handle,
            SecretHandle::new("mcp_notion_access_token").unwrap(),
            "registry descriptor must remain authoritative on a hit"
        );
    }

    /// Absent from BOTH registry and request → empty (unchanged fail-safe).
    #[test]
    fn mcp_planner_absent_from_registry_and_request_yields_no_injections() {
        let registry = Arc::new(SharedExtensionRegistry::new(registry_with_notion()));
        let planner = RegistryMcpEgressPlanner::new(registry);
        let provider = ExtensionId::new("notion").unwrap();
        let discovered = CapabilityId::new("notion.echo-broker-test__echo_ping").unwrap();
        let endpoint = HostedMcpEndpoint::parse(NOTION_MCP_URL).unwrap();

        let injections = planner.credential_injections(&provider, &discovered, &endpoint, &[]);

        assert!(injections.is_empty());
    }

    /// Distinct from the absence case above: `get_capability` returns `Some`
    /// for `capability_id`, but the descriptor's provider does NOT match the
    /// requesting provider. This pins the `.filter(provider match)` arm of the
    /// fallback specifically (see the comment on `credential_injections`) —
    /// the mismatch must fall through to `request_credentials`, not to empty.
    #[test]
    fn mcp_planner_falls_back_to_request_credentials_on_provider_mismatch() {
        let registry = Arc::new(SharedExtensionRegistry::new(registry_with_notion()));
        let planner = RegistryMcpEgressPlanner::new(registry);
        // The registry descriptor for this capability id is owned by "notion";
        // request as a different provider so `get_capability` hits but the
        // provider filter rejects it.
        let wrong_provider = ExtensionId::new("not-notion").unwrap();
        let registry_cap = CapabilityId::new("notion.notion-search").unwrap();
        let endpoint = HostedMcpEndpoint::parse(NOTION_MCP_URL).unwrap();
        let request_credentials = vec![request_credential("fallback_only_token", NOTION_MCP_HOST)];

        let injections = planner.credential_injections(
            &wrong_provider,
            &registry_cap,
            &endpoint,
            &request_credentials,
        );

        assert_eq!(injections.len(), 1);
        assert_eq!(
            injections[0].handle,
            SecretHandle::new("fallback_only_token").unwrap(),
            "provider mismatch on a registry hit must fall through to request credentials"
        );
    }

    /// Multiple request-provided credentials: every audience-matching one is
    /// injected, and the non-matching-audience one is dropped — the fallback
    /// applies the same per-credential filter as the registry path, not an
    /// all-or-nothing gate.
    #[test]
    fn mcp_planner_fallback_injects_all_audience_matching_request_credentials() {
        let registry = Arc::new(SharedExtensionRegistry::new(registry_with_notion()));
        let planner = RegistryMcpEgressPlanner::new(registry);
        let provider = ExtensionId::new("notion").unwrap();
        let discovered = CapabilityId::new("notion.echo-broker-test__echo_ping").unwrap();
        let endpoint = HostedMcpEndpoint::parse(NOTION_MCP_URL).unwrap();
        let request_credentials = vec![
            request_credential("mcp_notion_access_token", NOTION_MCP_HOST),
            request_credential("mcp_notion_secondary_token", NOTION_MCP_HOST),
            request_credential("wrong_audience_token", "other.example.com"),
        ];

        let injections =
            planner.credential_injections(&provider, &discovered, &endpoint, &request_credentials);

        let handles: Vec<_> = injections
            .iter()
            .map(|injection| injection.handle.clone())
            .collect();
        assert_eq!(injections.len(), 2, "both matching-audience creds inject");
        assert!(handles.contains(&SecretHandle::new("mcp_notion_access_token").unwrap()));
        assert!(handles.contains(&SecretHandle::new("mcp_notion_secondary_token").unwrap()));
        assert!(
            !handles.contains(&SecretHandle::new("wrong_audience_token").unwrap()),
            "non-matching-audience credential must be dropped"
        );
    }

    /// Test-through-the-caller: the public `plan` seam a discovered `tools/call`
    /// actually hits must carry the staged injection built from the request's
    /// runtime credentials, with the provider network policy still locked.
    #[test]
    fn planner_injects_request_credentials_for_discovered_capability_via_plan() {
        let registry = Arc::new(SharedExtensionRegistry::new(registry_with_notion()));
        let planner = RegistryMcpEgressPlanner::new(registry);
        let provider = ExtensionId::new("notion").unwrap();
        let discovered = CapabilityId::new("notion.echo-broker-test__echo_ping").unwrap();
        let scope = sample_scope();
        let request_credentials = vec![request_credential(
            "mcp_notion_access_token",
            NOTION_MCP_HOST,
        )];

        let plan = planner.plan(sample_plan_request(
            &provider,
            &discovered,
            NOTION_MCP_URL,
            &scope,
            &request_credentials,
        ));

        assert_eq!(plan.credential_injections.len(), 1);
        assert_eq!(
            plan.credential_injections[0].handle,
            SecretHandle::new("mcp_notion_access_token").unwrap()
        );
        assert_eq!(
            plan.network_policy.allowed_targets[0].host_pattern,
            NOTION_MCP_HOST
        );
    }

    // ── provider scoping ───────────────────────────────────────────────────

    #[test]
    fn planner_denies_unknown_provider() {
        let registry = Arc::new(SharedExtensionRegistry::new(registry_with_notion()));
        let planner = RegistryMcpEgressPlanner::new(registry);
        let provider = ExtensionId::new("not-notion").unwrap();
        let cap = CapabilityId::new("notion.notion-search").unwrap();

        let scope = sample_scope();
        let plan = planner.plan(sample_plan_request(
            &provider,
            &cap,
            "https://mcp.notion.com/mcp",
            &scope,
            &[],
        ));

        assert!(plan.credential_injections.is_empty());
        assert!(plan.network_policy.allowed_targets.is_empty());
    }

    #[test]
    fn planner_accepts_any_host_bundled_http_mcp_provider() {
        let registry = Arc::new(SharedExtensionRegistry::new(registry_with_provider(
            "fixture",
            "https://fixture.example.com/mcp",
            "fixture.search",
            "fixture_token",
        )));
        let planner = RegistryMcpEgressPlanner::new(registry);
        let provider = ExtensionId::new("fixture").unwrap();
        let cap = CapabilityId::new("fixture.search").unwrap();
        let scope = sample_scope();

        let plan = planner.plan(sample_plan_request(
            &provider,
            &cap,
            "https://fixture.example.com/mcp",
            &scope,
            &[],
        ));

        assert_eq!(plan.credential_injections.len(), 1);
        assert_eq!(
            plan.network_policy.allowed_targets[0].host_pattern,
            "fixture.example.com"
        );
    }

    #[test]
    fn planner_denies_wrong_host_for_notion_provider() {
        let registry = Arc::new(SharedExtensionRegistry::new(registry_with_notion()));
        let planner = RegistryMcpEgressPlanner::new(registry);
        let provider = ExtensionId::new("notion").unwrap();
        let cap = CapabilityId::new("notion.notion-search").unwrap();
        let scope = sample_scope();

        let plan = planner.plan(sample_plan_request(
            &provider,
            &cap,
            "https://evil.example.com/mcp",
            &scope,
            &[],
        ));

        assert!(plan.credential_injections.is_empty());
        assert!(plan.network_policy.allowed_targets.is_empty());
    }

    #[test]
    fn planner_denies_http_scheme_for_notion_provider() {
        let registry = Arc::new(SharedExtensionRegistry::new(registry_with_notion()));
        let planner = RegistryMcpEgressPlanner::new(registry);
        let provider = ExtensionId::new("notion").unwrap();
        let cap = CapabilityId::new("notion.notion-search").unwrap();
        let scope = sample_scope();

        let plan = planner.plan(sample_plan_request(
            &provider,
            &cap,
            "http://mcp.notion.com/mcp",
            &scope,
            &[],
        ));

        assert!(plan.credential_injections.is_empty());
    }

    #[test]
    fn planner_denies_wrong_path_for_notion_provider() {
        let registry = Arc::new(SharedExtensionRegistry::new(registry_with_notion()));
        let planner = RegistryMcpEgressPlanner::new(registry);
        let provider = ExtensionId::new("notion").unwrap();
        let cap = CapabilityId::new("notion.notion-search").unwrap();
        let scope = sample_scope();

        let plan = planner.plan(sample_plan_request(
            &provider,
            &cap,
            "https://mcp.notion.com/other",
            &scope,
            &[],
        ));

        assert!(plan.credential_injections.is_empty());
    }

    // ── happy path policy ─────────────────────────────────────────────────

    #[test]
    fn planner_emits_locked_policy_for_notion_provider() {
        let registry = Arc::new(SharedExtensionRegistry::new(registry_with_notion()));
        let planner = RegistryMcpEgressPlanner::new(registry);
        let provider = ExtensionId::new("notion").unwrap();
        let cap = CapabilityId::new("notion.notion-search").unwrap();
        let scope = sample_scope();

        let plan = planner.plan(sample_plan_request(
            &provider,
            &cap,
            "https://mcp.notion.com/mcp",
            &scope,
            &[],
        ));

        assert_eq!(plan.credential_injections.len(), 1);
        assert!(plan.network_policy.deny_private_ip_ranges);
        assert_eq!(plan.network_policy.allowed_targets.len(), 1);
        assert_eq!(
            plan.network_policy.allowed_targets[0].host_pattern,
            NOTION_MCP_HOST.to_string()
        );
        assert_eq!(
            plan.network_policy.allowed_targets[0].scheme,
            Some(NetworkScheme::Https)
        );
        assert_eq!(plan.response_body_limit, Some(MCP_RESPONSE_BODY_LIMIT));
        assert_eq!(plan.timeout_ms, Some(MCP_TIMEOUT_MS));
    }

    // ── URL allowlist unit tests ───────────────────────────────────────────

    #[test]
    fn hosted_mcp_url_allowed_accepts_canonical_notion_url() {
        let endpoint = HostedMcpEndpoint::parse(NOTION_MCP_URL).unwrap();
        assert!(hosted_mcp_url_allowed(NOTION_MCP_URL, &endpoint));
    }

    #[test]
    fn hosted_mcp_url_allowed_rejects_http_scheme() {
        let endpoint = HostedMcpEndpoint::parse(NOTION_MCP_URL).unwrap();
        assert!(!hosted_mcp_url_allowed(
            "http://mcp.notion.com/mcp",
            &endpoint
        ));
    }

    #[test]
    fn hosted_mcp_url_allowed_rejects_wrong_host() {
        let endpoint = HostedMcpEndpoint::parse(NOTION_MCP_URL).unwrap();
        assert!(!hosted_mcp_url_allowed(
            "https://evil.example.com/mcp",
            &endpoint
        ));
    }

    #[test]
    fn hosted_mcp_url_allowed_rejects_wrong_path() {
        let endpoint = HostedMcpEndpoint::parse(NOTION_MCP_URL).unwrap();
        assert!(!hosted_mcp_url_allowed(
            "https://mcp.notion.com/other",
            &endpoint
        ));
    }

    #[test]
    fn hosted_mcp_url_allowed_accepts_trailing_slash() {
        let endpoint = HostedMcpEndpoint::parse(NOTION_MCP_URL).unwrap();
        assert!(hosted_mcp_url_allowed(
            "https://mcp.notion.com/mcp/",
            &endpoint
        ));
    }

    #[test]
    fn hosted_mcp_url_allowed_rejects_extra_url_components() {
        let endpoint = HostedMcpEndpoint::parse(NOTION_MCP_URL).unwrap();

        assert!(!hosted_mcp_url_allowed(
            "https://mcp.notion.com/mcp?token=shadow",
            &endpoint
        ));
        assert!(!hosted_mcp_url_allowed(
            "https://mcp.notion.com/mcp#fragment",
            &endpoint
        ));
        assert!(!hosted_mcp_url_allowed(
            "https://user@mcp.notion.com/mcp",
            &endpoint
        ));
    }

    // ── helpers ───────────────────────────────────────────────────────────

    fn sample_scope() -> ResourceScope {
        ResourceScope {
            tenant_id: TenantId::new("test-tenant").unwrap(),
            user_id: UserId::new("test-user").unwrap(),
            agent_id: None,
            project_id: Some(ProjectId::new("test-project").unwrap()),
            mission_id: None,
            thread_id: None,
            invocation_id: InvocationId::new(),
        }
    }

    fn sample_plan_request<'a>(
        provider: &'a ExtensionId,
        capability_id: &'a CapabilityId,
        url: &'a str,
        scope: &'a ResourceScope,
        runtime_credentials: &'a [RuntimeCredentialRequirement],
    ) -> McpHostHttpEgressPlanRequest<'a> {
        McpHostHttpEgressPlanRequest {
            provider,
            capability_id,
            scope,
            transport: "http",
            method: NetworkMethod::Post,
            url,
            headers: &[],
            body: &[],
            runtime_credentials,
        }
    }

    /// A host-resolved credential requirement as the dispatcher threads it onto
    /// the request for a discovered capability (mirrors the shape
    /// `registry_with_provider` publishes into the registry descriptor).
    fn request_credential(handle: &str, audience_host: &str) -> RuntimeCredentialRequirement {
        RuntimeCredentialRequirement {
            handle: SecretHandle::new(handle).unwrap(),
            source: RuntimeCredentialRequirementSource::ProductAuthAccount {
                provider: RuntimeCredentialAccountProviderId::new("notion").unwrap(),
                setup: Default::default(),
            },
            provider_scopes: Vec::new(),
            audience: NetworkTargetPattern {
                scheme: Some(NetworkScheme::Https),
                host_pattern: audience_host.to_string(),
                port: None,
            },
            target: RuntimeCredentialTarget::Header {
                name: "authorization".to_string(),
                prefix: Some("Bearer ".to_string()),
            },
            required: true,
        }
    }

    fn registry_with_notion() -> ironclaw_extensions::ExtensionRegistry {
        registry_with_provider(
            "notion",
            NOTION_MCP_URL,
            "notion.notion-search",
            "mcp_notion_access_token",
        )
    }

    fn registry_with_provider(
        provider: &str,
        url: &str,
        capability_id: &str,
        credential_handle: &str,
    ) -> ironclaw_extensions::ExtensionRegistry {
        let mut registry = ironclaw_extensions::ExtensionRegistry::new();
        let host = url::Url::parse(url)
            .unwrap()
            .host_str()
            .unwrap()
            .to_string();
        registry
            .insert(
                ExtensionPackage::from_manifest(
                    ExtensionManifest {
                        schema_version: ironclaw_extensions::MANIFEST_SCHEMA_VERSION.to_string(),
                        id: ExtensionId::new(provider).unwrap(),
                        name: provider.to_string(),
                        version: "0.1.0".to_string(),
                        description: "Hosted MCP".to_string(),
                        source: ManifestSource::HostBundled,
                        requested_trust: ironclaw_host_api::RequestedTrustClass::ThirdParty,
                        descriptor_trust_default: TrustClass::Sandbox,
                        runtime: ironclaw_extensions::ExtensionRuntime::Mcp {
                            transport: "http".to_string(),
                            command: None,
                            args: Vec::new(),
                            url: Some(url.to_string()),
                        },
                        host_apis: Vec::new(),
                        hooks: Vec::new(),
                        capabilities: vec![ironclaw_extensions::CapabilityManifest {
                            id: CapabilityId::new(capability_id).unwrap(),
                            implements: Vec::new(),
                            description: "Search".to_string(),
                            effects: vec![
                                ironclaw_host_api::EffectKind::DispatchCapability,
                                ironclaw_host_api::EffectKind::Network,
                                ironclaw_host_api::EffectKind::UseSecret,
                            ],
                            default_permission: PermissionMode::Allow,
                            visibility: ironclaw_extensions::CapabilityVisibility::Model,
                            input_schema_ref: CapabilityProfileSchemaRef::new(
                                "schemas/notion/notion-search.input.v1.json",
                            )
                            .unwrap(),
                            output_schema_ref: CapabilityProfileSchemaRef::new(
                                "schemas/notion/notion-search.output.v1.json",
                            )
                            .unwrap(),
                            prompt_doc_ref: None,
                            required_host_ports: Vec::new(),
                            runtime_credentials: vec![
                                ironclaw_host_api::RuntimeCredentialRequirement {
                                    handle: SecretHandle::new(credential_handle).unwrap(),
                                    source:
                                        RuntimeCredentialRequirementSource::ProductAuthAccount {
                                            provider: RuntimeCredentialAccountProviderId::new(
                                                provider,
                                            )
                                            .unwrap(),
                                            setup: Default::default(),
                                        },
                                    provider_scopes: Vec::new(),
                                    audience: NetworkTargetPattern {
                                        scheme: Some(NetworkScheme::Https),
                                        host_pattern: host,
                                        port: None,
                                    },
                                    target: RuntimeCredentialTarget::Header {
                                        name: "authorization".to_string(),
                                        prefix: Some("Bearer ".to_string()),
                                    },
                                    required: true,
                                },
                            ],
                            resource_profile: None,
                        }],
                    },
                    VirtualPath::new(format!("/system/extensions/{provider}")).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        registry
    }
}
