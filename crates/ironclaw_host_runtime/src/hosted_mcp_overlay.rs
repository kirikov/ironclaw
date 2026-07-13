//! Per-user hosted-MCP capability-surface overlay.
//!
//! Boot-time extension activation publishes a package's *static* capability
//! floor into the shared global registry (see
//! `ironclaw_reborn_composition::extension_host::extension_lifecycle`), which
//! is why host-bundled tools like `marketplace.submit_deliverable` stay
//! visible to every turn. A hosted-MCP provider additionally exposes a live
//! `tools/list` surface that is scoped to the *caller's own* credentials —
//! that surface must never be written into the shared registry (it would
//! either leak across users or clobber the static floor). This module is the
//! seam a composition-owned implementation uses to fetch that per-caller
//! surface at request time; [`crate::surface::CapabilityCatalog`] unions the
//! result onto the static floor without ever mutating the registry.
//!
//! [`HireScope`] is the fail-closed leak gate: it is constructible only from
//! a [`ResourceScope`] that already carries an `agent_id`, so a caller with
//! no agent identity (buyer/operator/system/cli turns) cannot reach hosted-MCP
//! discovery at all — not "discovery returns nothing," but "discovery is
//! never called."

use async_trait::async_trait;
use ironclaw_extensions::ExtensionPackage;
use ironclaw_host_api::{
    AgentId, CapabilityDescriptor, InvocationId, ProjectId, ResourceScope, TenantId, UserId,
};

/// Owner identity of a provisioned hire.
///
/// This is the S1 leak gate: the sole constructor is [`Self::from_scope`],
/// which requires the source [`ResourceScope`] to carry `Some(agent_id)`.
/// Fields are private and there is deliberately no `From<ResourceScope>`, no
/// `Default`, and no second constructor — a None-agent turn must be
/// structurally unable to mint a `HireScope`, reach hosted-MCP discovery, or
/// populate its cache. Do not add a way around `from_scope`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HireScope {
    tenant_id: TenantId,
    user_id: UserId,
    agent_id: AgentId,
    project_id: Option<ProjectId>,
    invocation_id: InvocationId,
}

impl HireScope {
    /// Builds a `HireScope` iff `scope.agent_id` is present. Returns `None`
    /// for buyer/operator/system/cli turns — callers must treat `None` as
    /// "serve the static floor only": never call discovery, never cache.
    pub fn from_scope(scope: &ResourceScope) -> Option<Self> {
        let agent_id = scope.agent_id.clone()?;
        Some(Self {
            tenant_id: scope.tenant_id.clone(),
            user_id: scope.user_id.clone(),
            agent_id,
            project_id: scope.project_id.clone(),
            invocation_id: scope.invocation_id,
        })
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    pub fn project_id(&self) -> Option<&ProjectId> {
        self.project_id.as_ref()
    }

    /// Owner-scope for the discovery lease: tenant/user/agent/project plus
    /// invocation, with mission/thread cleared — mirrors
    /// `ResourceScope::without_thread_and_mission`, except `agent_id` is
    /// structurally guaranteed present here rather than merely preserved.
    pub fn to_owner_scope(&self) -> ResourceScope {
        ResourceScope {
            tenant_id: self.tenant_id.clone(),
            user_id: self.user_id.clone(),
            agent_id: Some(self.agent_id.clone()),
            project_id: self.project_id.clone(),
            mission_id: None,
            thread_id: None,
            invocation_id: self.invocation_id,
        }
    }
}

/// Discovery failure classification returned by a
/// [`HostedMcpSurfaceOverlay`] implementation. Both variants — and a budget
/// timeout at the call site — resolve to "serve the static floor only, do
/// not cache, never fail the turn."
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostedMcpOverlayError {
    /// Retryable: network/backend hiccup, empty `tools/list`, or no
    /// resolvable per-agent credential lease yet.
    Transient(String),
    /// Not retryable without a manifest/config change.
    Permanent(String),
}

/// Per-user hosted-MCP capability-surface source.
///
/// Implementations fetch the live tool surface one hire is entitled to for a
/// single hosted-MCP `package`, scoped by [`HireScope`] so discovery and any
/// caching stay structurally tied to a real agent identity. Returned
/// descriptors must carry inline `parameters_schema` (no `$ref`) — see
/// `ironclaw_extensions::package_with_discovered_hosted_mcp_tools`.
#[async_trait]
pub trait HostedMcpSurfaceOverlay: Send + Sync {
    async fn overlay_capabilities(
        &self,
        hire: &HireScope,
        package: &ExtensionPackage,
    ) -> Result<Vec<CapabilityDescriptor>, HostedMcpOverlayError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironclaw_host_api::MissionId;

    fn scope_with_agent(agent_id: Option<&str>) -> ResourceScope {
        ResourceScope {
            tenant_id: TenantId::new("acme").unwrap(),
            user_id: UserId::new("user-1").unwrap(),
            agent_id: agent_id.map(|id| AgentId::new(id).unwrap()),
            project_id: Some(ProjectId::new("proj-1").unwrap()),
            mission_id: Some(MissionId::new("mission-1").unwrap()),
            thread_id: None,
            invocation_id: InvocationId::new(),
        }
    }

    #[test]
    fn from_scope_is_none_without_agent_id() {
        assert!(HireScope::from_scope(&scope_with_agent(None)).is_none());
    }

    #[test]
    fn from_scope_is_some_with_agent_id() {
        let hire = HireScope::from_scope(&scope_with_agent(Some("agent-1")));
        assert!(hire.is_some());
        assert_eq!(hire.unwrap().agent_id().as_str(), "agent-1");
    }

    #[test]
    fn to_owner_scope_keeps_owner_identity_but_clears_mission_and_thread() {
        let scope = scope_with_agent(Some("agent-1"));
        let hire = HireScope::from_scope(&scope).expect("agent present");
        let owner_scope = hire.to_owner_scope();

        assert_eq!(owner_scope.tenant_id, scope.tenant_id);
        assert_eq!(owner_scope.user_id, scope.user_id);
        assert_eq!(owner_scope.agent_id, scope.agent_id);
        assert_eq!(owner_scope.project_id, scope.project_id);
        assert_eq!(owner_scope.invocation_id, scope.invocation_id);
        assert!(owner_scope.mission_id.is_none());
        assert!(owner_scope.thread_id.is_none());
    }
}
