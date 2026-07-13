use std::sync::Arc;

use ironclaw_extensions::{
    ExtensionPackage, ExtensionRegistry, ExtensionRuntime, SharedExtensionRegistry,
    package_with_discovered_hosted_mcp_tools,
};
use ironclaw_host_api::{ResourceScope, RuntimeHttpEgress};
use ironclaw_mcp::{McpClient, McpClientRequest, McpHostHttpClient, McpRuntimeHttpAdapter};

use crate::extension_host::mcp::{MCP_RESPONSE_BODY_LIMIT, RegistryMcpEgressPlanner};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostedMcpDiscoveryError {
    Transient(String),
    Permanent(String),
}

pub(crate) async fn discover_hosted_mcp_package(
    package: &ExtensionPackage,
    scope: ResourceScope,
    runtime_http_egress: Arc<dyn RuntimeHttpEgress>,
) -> Result<ExtensionPackage, HostedMcpDiscoveryError> {
    let (transport, command, args, url) = match &package.manifest.runtime {
        ExtensionRuntime::Mcp {
            transport,
            command,
            args,
            url,
        } if is_hosted_http_mcp_package(package) => (
            transport.clone(),
            command.clone(),
            args.clone(),
            url.clone(),
        ),
        _ => {
            return Err(HostedMcpDiscoveryError::Permanent(format!(
                "extension {} is not a host-bundled hosted MCP provider",
                package.id
            )));
        }
    };
    let registry = Arc::new(SharedExtensionRegistry::new(ExtensionRegistry::new()));
    registry.upsert(package.clone()).map_err(|error| {
        HostedMcpDiscoveryError::Permanent(format!(
            "failed to prepare hosted MCP discovery: {error}"
        ))
    })?;
    let planning_capability_id = package
        .manifest
        .capabilities
        .first()
        .map(|capability| capability.id.clone())
        .ok_or_else(|| {
            HostedMcpDiscoveryError::Permanent(format!(
                "hosted MCP provider {} has no capability template",
                package.id
            ))
        })?;
    let client = McpHostHttpClient::new(
        McpRuntimeHttpAdapter::new(runtime_http_egress),
        RegistryMcpEgressPlanner::new(registry),
    );
    let output = client
        .discover_tools(McpClientRequest {
            provider: package.id.clone(),
            capability_id: planning_capability_id,
            scope,
            transport,
            command,
            args,
            url,
            input: serde_json::Value::Null,
            max_output_bytes: MCP_RESPONSE_BODY_LIMIT,
        })
        .await
        .map_err(|error| HostedMcpDiscoveryError::Transient(error.stable_reason().to_string()))?;
    if output.tools.is_empty() {
        // follow-up: a successful-but-empty `tools/list` (a real, valid
        // "this hire currently has zero grants" state) is mapped to
        // `Transient` here, same as a network/backend failure — the caller
        // (`CompositionHostedMcpOverlay`) only caches `Ok` results, so this
        // never gets cached and a zero-tool hire re-pays the full discovery
        // round trip (up to the surface budget) on every turn, forever. A
        // successful-but-empty discovery is distinguishable from an outage
        // (the round trip succeeded) and could be cached as a valid
        // negative without violating error-handling.md's "don't cache
        // failures" rule. Deferred — this call site would need a third
        // outcome variant threaded through `HostedMcpDiscoveryError`/
        // `HostedMcpOverlayError`, not a mechanical fix.
        return Err(HostedMcpDiscoveryError::Transient(format!(
            "hosted MCP provider {} returned no discoverable tools",
            package.id
        )));
    }
    package_with_discovered_hosted_mcp_tools(package, &output.tools)
        .map_err(|error| HostedMcpDiscoveryError::Permanent(error.to_string()))
}

pub(crate) use ironclaw_extensions::is_hosted_http_mcp_package;
