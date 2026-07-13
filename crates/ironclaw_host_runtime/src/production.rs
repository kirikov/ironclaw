//! Production composition of the [`HostRuntime`] contract.
//!
//! [`DefaultHostRuntime`] is the contract-level facade that upper turn/loop
//! services should depend on. Internally it composes
//! [`ironclaw_capabilities::CapabilityHost`] with neutral kernel services —
//! extension registry, capability dispatcher, trust-aware authorizer,
//! run-state and approval stores, capability-lease store, and process
//! manager.
//!
//! This layer evaluates the package's manifest-derived trust input immediately
//! before invoking [`CapabilityHost`] so authorization consumes a host-owned
//! [`TrustDecision`](ironclaw_trust::TrustDecision) instead of caller-supplied
//! claims. The default fail-closed policy denies authority until composition
//! supplies a concrete host policy.

use std::{sync::Arc, time::Instant};

use async_trait::async_trait;
use futures_util::future::join_all;
use ironclaw_approvals::{
    PersistentApprovalAction, PersistentApprovalPolicyKey, PersistentApprovalPolicyStore,
    PersistentApprovalScope, permission_mode_allows_persistent_approval,
};
use ironclaw_authorization::{CapabilityLeaseStore, TrustAwareCapabilityDispatchAuthorizer};
use ironclaw_capabilities::{
    CapabilityAuthResumeRequest, CapabilityHost, CapabilityInvocationError,
    CapabilityInvocationRequest, CapabilityInvocationResult, CapabilityObligationHandler,
    CapabilityResumeRequest, CapabilitySpawnRequest, CapabilitySpawnResult,
};
use ironclaw_extensions::{ExtensionPackage, ExtensionRegistry, SharedExtensionRegistry};
use ironclaw_filesystem::RootFilesystem;
use ironclaw_host_api::{
    ApprovalRequestId, CapabilityDispatcher, CapabilityId, Decision, DispatchFailureKind,
    InvocationId, PackageSource, Principal, ResourceEstimate, ResourceScope,
    RuntimeCredentialAuthRequirement, RuntimeDispatchErrorKind, RuntimeKind, SecretHandle,
    runtime_policy::EffectiveRuntimePolicy, sha256_digest_token,
};
use ironclaw_observability::live_latency_started_at;
use ironclaw_process_sandbox::{
    PROCESS_SANDBOX_CAPABILITY_ID, SandboxProcessPlan, ValidatedSandboxProcessPlan,
};
use ironclaw_processes::{
    ProcessCancellationRegistry, ProcessError, ProcessHost, ProcessManager, ProcessResultStore,
    ProcessStart, ProcessStatus, ProcessStore,
};
use ironclaw_run_state::{
    ApprovalRequestStore, RunStateApprovalStore, RunStateError, RunStateStore, RunStatus,
};
use ironclaw_secrets::SecretStore;
use ironclaw_trust::{HostTrustPolicy, TrustDecision, TrustError, TrustPolicy, TrustProvenance};
use ironclaw_turns::run_profile::LoopSafeSummary;

fn trace_capability_latency_ok(
    operation: &'static str,
    capability_id: &CapabilityId,
    scope: &ResourceScope,
    started_at: Option<Instant>,
) {
    ironclaw_observability::live_latency_trace_ok!(
        "host_runtime",
        operation,
        started_at,
        capability_id = %capability_id,
        tenant_id = %scope.tenant_id,
        user_id = %scope.user_id,
        agent_id = scope.agent_id.as_ref().map(|id| id.as_str()).unwrap_or(""),
        project_id = scope.project_id.as_ref().map(|id| id.as_str()).unwrap_or(""),
        mission_id = scope.mission_id.as_ref().map(|id| id.as_str()).unwrap_or(""),
        thread_id = scope.thread_id.as_ref().map(|id| id.as_str()).unwrap_or(""),
        invocation_id = %scope.invocation_id,
        "host runtime capability operation completed",
    );
}

fn trace_capability_latency_error<E: ?Sized>(
    operation: &'static str,
    capability_id: &CapabilityId,
    scope: &ResourceScope,
    started_at: Option<Instant>,
    _error: &E,
) {
    ironclaw_observability::live_latency_trace_error!(
        "host_runtime",
        operation,
        started_at,
        "error",
        capability_id = %capability_id,
        tenant_id = %scope.tenant_id,
        user_id = %scope.user_id,
        agent_id = scope.agent_id.as_ref().map(|id| id.as_str()).unwrap_or(""),
        project_id = scope.project_id.as_ref().map(|id| id.as_str()).unwrap_or(""),
        mission_id = scope.mission_id.as_ref().map(|id| id.as_str()).unwrap_or(""),
        thread_id = scope.thread_id.as_ref().map(|id| id.as_str()).unwrap_or(""),
        invocation_id = %scope.invocation_id,
        "host runtime capability operation failed",
    );
}

use crate::{
    BuiltinObligationHandler, BuiltinObligationServices, CancelRuntimeWorkOutcome,
    CancelRuntimeWorkRequest, CapabilitySurfaceVersion, HostRuntime, HostRuntimeError,
    HostRuntimeHealth, HostRuntimeStatus, HostedMcpSurfaceOverlay, RuntimeApprovalGate,
    RuntimeAuthGate, RuntimeBackendHealth, RuntimeBlockedReason,
    RuntimeCapabilityAuthResumeRequest, RuntimeCapabilityCompleted, RuntimeCapabilityFailure,
    RuntimeCapabilityOutcome, RuntimeCapabilityRequest, RuntimeCapabilityResumeRequest,
    RuntimeFailureKind, RuntimeGateId, RuntimeStatusRequest, RuntimeWorkId, RuntimeWorkSummary,
    VisibleCapabilityRequest, VisibleCapabilitySurface, obligations::secret_present,
    plan_capability, surface::CapabilityCatalog,
};

/// Default production wiring for [`HostRuntime`].
pub struct DefaultHostRuntime {
    registry: Arc<SharedExtensionRegistry>,
    dispatcher: Arc<dyn CapabilityDispatcher>,
    authorizer: Arc<dyn TrustAwareCapabilityDispatchAuthorizer>,
    trust_policy: Arc<dyn TrustPolicy>,
    run_state: Option<Arc<dyn RunStateStore>>,
    approval_requests: Option<Arc<dyn ApprovalRequestStore>>,
    run_state_approval_store: Option<Arc<dyn RunStateApprovalStore>>,
    capability_leases: Option<Arc<dyn CapabilityLeaseStore>>,
    // arch-exempt: optional_arc, minimal/test compositions intentionally disable
    // persistent approval replay until the product revoke control plane is split out,
    // plan #4539
    persistent_approval_policies: Option<Arc<dyn PersistentApprovalPolicyStore>>,
    process_manager: Option<Arc<dyn ProcessManager>>,
    process_store: Option<Arc<dyn ProcessStore>>,
    process_result_store: Option<Arc<dyn ProcessResultStore>>,
    process_cancellation_registry: Option<Arc<ProcessCancellationRegistry>>,
    surface_filesystem: Option<Arc<dyn RootFilesystem>>,
    // arch-exempt: optional_arc, hosted-MCP overlay discovery requires HTTP
    // egress + a secret store; minimal/test host-runtime graphs legitimately
    // ship without it (see `attach_hosted_mcp_runtime` soft-disable), plan #4539
    hosted_mcp_overlay: Option<Arc<dyn HostedMcpSurfaceOverlay>>,
    runtime_health: Option<Arc<dyn RuntimeBackendHealth>>,
    obligation_handler: Option<Arc<dyn CapabilityObligationHandler>>,
    /// Optional secret store used for pre-flight credential presence checks.
    ///
    /// When present, capability dispatch (both `invoke_capability` and
    /// `spawn_capability`) checks whether all required credentials declared in the
    /// capability manifest are present before the authorization step. This surfaces
    /// `AuthRequired` ahead of the approval gate so users are never asked to
    /// approve an action that cannot yet execute.
    ///
    /// When absent the pre-flight is skipped; the dispatch-time obligation check
    /// remains the enforcement backstop regardless.
    // arch-exempt: optional_arc, credential pre-flight is disabled in minimal/test
    // host-runtime graphs that do not wire a secret store, plan #4539 (Fix B)
    credential_preflight_store: Option<Arc<dyn SecretStore>>,
    surface_version: CapabilitySurfaceVersion,
    runtime_policy: EffectiveRuntimePolicy,
}

impl DefaultHostRuntime {
    /// Constructs a default host runtime over the supplied kernel services.
    ///
    /// This constructor snapshots the supplied registry into an internal
    /// [`SharedExtensionRegistry`]. Use [`Self::from_shared_registry`] when
    /// callers need subsequent registry mutations to be shared with the runtime.
    ///
    /// The runtime starts with an explicit fail-closed host trust policy, so
    /// capability dispatch is denied until composition attaches a concrete
    /// policy with [`Self::with_trust_policy`] or [`Self::with_trust_policy_dyn`].
    ///
    /// Callers must additionally attach either a combined
    /// [`RunStateApprovalStore`] via
    /// [`with_run_state_approval_store`](Self::with_run_state_approval_store),
    /// or separate stores via [`with_run_state`](Self::with_run_state) and
    /// [`with_approval_requests`](Self::with_approval_requests), before
    /// invoking any capability whose authorizer may return
    /// `RequireApproval`. Without those stores the capability host fails
    /// closed with `ApprovalStoreMissing`, which surfaces here as a
    /// [`RuntimeCapabilityOutcome::Failed`] rather than blocking for human
    /// review.
    pub fn new(
        registry: Arc<ExtensionRegistry>,
        dispatcher: Arc<dyn CapabilityDispatcher>,
        authorizer: Arc<dyn TrustAwareCapabilityDispatchAuthorizer>,
        surface_version: CapabilitySurfaceVersion,
        runtime_policy: EffectiveRuntimePolicy,
    ) -> Self {
        Self::from_shared_registry(
            Arc::new(SharedExtensionRegistry::new((*registry).clone())),
            dispatcher,
            authorizer,
            surface_version,
            runtime_policy,
        )
    }

    pub fn from_shared_registry(
        registry: Arc<SharedExtensionRegistry>,
        dispatcher: Arc<dyn CapabilityDispatcher>,
        authorizer: Arc<dyn TrustAwareCapabilityDispatchAuthorizer>,
        surface_version: CapabilitySurfaceVersion,
        runtime_policy: EffectiveRuntimePolicy,
    ) -> Self {
        Self {
            registry,
            dispatcher,
            authorizer,
            trust_policy: Arc::new(HostTrustPolicy::fail_closed()),
            run_state: None,
            approval_requests: None,
            run_state_approval_store: None,
            capability_leases: None,
            persistent_approval_policies: None,
            process_manager: None,
            process_store: None,
            process_result_store: None,
            process_cancellation_registry: None,
            surface_filesystem: None,
            hosted_mcp_overlay: None,
            runtime_health: None,
            obligation_handler: None,
            credential_preflight_store: None,
            surface_version,
            runtime_policy,
        }
    }

    /// Attaches the host-owned trust policy used to evaluate each provider's
    /// manifest-derived trust input immediately before capability dispatch.
    pub fn with_trust_policy<T>(mut self, trust_policy: Arc<T>) -> Self
    where
        T: TrustPolicy + 'static,
    {
        self.trust_policy = trust_policy;
        self
    }

    /// Attaches an already-erased host-owned trust policy.
    pub fn with_trust_policy_dyn(mut self, trust_policy: Arc<dyn TrustPolicy>) -> Self {
        self.trust_policy = trust_policy;
        self
    }

    /// Attaches the resolved runtime policy that structurally gates each
    /// capability invocation and visible-capability projection.
    pub fn with_runtime_policy(mut self, policy: EffectiveRuntimePolicy) -> Self {
        self.runtime_policy = policy;
        self
    }

    pub fn with_surface_filesystem(mut self, filesystem: Arc<dyn RootFilesystem>) -> Self {
        self.surface_filesystem = Some(filesystem);
        self
    }

    /// Attaches the per-user hosted-MCP capability-surface overlay. Absent,
    /// `visible_capabilities` serves the static registry floor only — see
    /// `crate::hosted_mcp_overlay` for the leak-gate this depends on.
    pub fn with_hosted_mcp_overlay(mut self, overlay: Arc<dyn HostedMcpSurfaceOverlay>) -> Self {
        self.hosted_mcp_overlay = Some(overlay);
        self
    }

    /// Attaches the run-state store used to record invocation lifecycle.
    pub fn with_run_state(mut self, run_state: Arc<dyn RunStateStore>) -> Self {
        self.run_state = Some(run_state);
        self.run_state_approval_store = None;
        self
    }

    /// Attaches the approval-request store used to persist approval prompts.
    pub fn with_approval_requests(
        mut self,
        approval_requests: Arc<dyn ApprovalRequestStore>,
    ) -> Self {
        self.approval_requests = Some(approval_requests);
        self.run_state_approval_store = None;
        self
    }

    /// Attaches a combined durable run-state/approval-request store with an
    /// atomic approval-block transition.
    pub fn with_run_state_approval_store(mut self, store: Arc<dyn RunStateApprovalStore>) -> Self {
        self.run_state = Some(store.clone());
        self.approval_requests = Some(store.clone());
        self.run_state_approval_store = Some(store);
        self
    }

    /// Attaches the capability-lease store used by approval resume paths.
    pub fn with_capability_leases(
        mut self,
        capability_leases: Arc<dyn CapabilityLeaseStore>,
    ) -> Self {
        self.capability_leases = Some(capability_leases);
        self
    }

    /// Attaches reusable approval policy overrides used to inject scoped,
    /// manifest-bounded grants before ordinary authorization.
    pub fn with_persistent_approval_policies(
        mut self,
        policies: Arc<dyn PersistentApprovalPolicyStore>,
    ) -> Self {
        self.persistent_approval_policies = Some(policies);
        self
    }

    /// Attaches the process manager used by future spawn paths.
    pub fn with_process_manager(mut self, process_manager: Arc<dyn ProcessManager>) -> Self {
        self.process_manager = Some(process_manager);
        self
    }

    /// Attaches the process store used for status and cancellation fanout.
    pub fn with_process_store(mut self, process_store: Arc<dyn ProcessStore>) -> Self {
        self.process_store = Some(process_store);
        self
    }

    /// Attaches the process result store used to persist cancellation results.
    pub fn with_process_result_store(
        mut self,
        process_result_store: Arc<dyn ProcessResultStore>,
    ) -> Self {
        self.process_result_store = Some(process_result_store);
        self
    }

    /// Attaches the process cancellation registry used to notify running
    /// background executors when `cancel_work` kills a process record.
    pub fn with_process_cancellation_registry(
        mut self,
        registry: Arc<ProcessCancellationRegistry>,
    ) -> Self {
        self.process_cancellation_registry = Some(registry);
        self
    }

    /// Attaches the backend health probe for concrete runtime implementations.
    pub fn with_runtime_health(mut self, health: Arc<dyn RuntimeBackendHealth>) -> Self {
        self.runtime_health = Some(health);
        self
    }

    /// Attaches a host-provided obligation handler.
    pub fn with_obligation_handler<T>(mut self, handler: Arc<T>) -> Self
    where
        T: CapabilityObligationHandler + 'static,
    {
        let handler: Arc<dyn CapabilityObligationHandler> = handler;
        self.obligation_handler = Some(handler);
        self
    }

    /// Attaches an already-erased host-provided obligation handler.
    pub fn with_obligation_handler_dyn(
        mut self,
        handler: Arc<dyn CapabilityObligationHandler>,
    ) -> Self {
        self.obligation_handler = Some(handler);
        self
    }

    /// Installs a fully configured built-in obligation handler using the shared
    /// service graph supplied by host-runtime composition.
    ///
    /// The `services` value owns the handoff stores that runtime adapters and
    /// HTTP egress wiring will consume, while the installed handler receives
    /// clones of the same stores for staging obligations before dispatch.
    pub fn with_builtin_obligation_services(self, services: &BuiltinObligationServices) -> Self {
        self.with_obligation_handler(Arc::new(services.obligation_handler()))
    }

    /// Installs the default built-in obligation handler with no optional backing
    /// stores. Obligations requiring audit/network/secret/resource backing still
    /// fail closed until the caller supplies a fully configured handler through
    /// [`Self::with_builtin_obligation_services`], [`Self::with_obligation_handler`],
    /// or [`Self::with_obligation_handler_dyn`].
    pub fn with_builtin_obligation_handler(self) -> Self {
        self.with_obligation_handler(Arc::new(BuiltinObligationHandler::new()))
    }

    /// Attaches the secret store used for credential pre-flight checks.
    ///
    /// When set, `invoke_capability` and `spawn_capability` query secret presence
    /// for all required credentials declared in the capability manifest *before*
    /// the approval gate fires. This prevents burning a human approval on an
    /// invocation that cannot yet succeed because a credential is missing.
    ///
    /// The dispatch-time obligation check remains the enforcement backstop
    /// regardless of whether this store is set.
    ///
    /// Production code must use `HostRuntimeServices::build_host_runtime()` which
    /// wires the secret store automatically. This setter is `pub(crate)` to prevent
    /// a second public seam for secret-store configuration on the production facade.
    // arch-exempt: optional_arc, genuinely optional — minimal/test graphs that
    // never need pre-flight skip this; production wires it from HostRuntimeServices,
    // plan #4539 (Fix B)
    pub(crate) fn with_credential_preflight_store(
        mut self,
        secret_store: Arc<dyn SecretStore>,
    ) -> Self {
        self.credential_preflight_store = Some(secret_store);
        self
    }

    /// Spawns an already-authorized process request through the configured
    /// process manager.
    pub async fn spawn_process(
        &self,
        start: ProcessStart,
    ) -> Result<crate::RuntimeProcessHandle, HostRuntimeError> {
        let Some(process_manager) = &self.process_manager else {
            return Err(HostRuntimeError::Unavailable {
                reason: "process manager unavailable".to_string(),
            });
        };
        let capability_id = start.capability_id.clone();
        let record = process_manager
            .spawn(start)
            .await
            .map_err(unavailable_from_process_error)?;
        Ok(crate::RuntimeProcessHandle {
            process_id: record.process_id,
            capability_id,
        })
    }
}

#[async_trait]
impl HostRuntime for DefaultHostRuntime {
    async fn invoke_capability(
        &self,
        request: RuntimeCapabilityRequest,
    ) -> Result<RuntimeCapabilityOutcome, HostRuntimeError> {
        let RuntimeCapabilityRequest {
            mut context,
            capability_id,
            estimate,
            input,
            idempotency_key,
            trust_decision: _caller_trust_decision,
        } = request;
        let scope = context.resource_scope.clone();
        let invocation_id = context.invocation_id;
        let total_started_at = live_latency_started_at();
        // Forward the (currently advisory) idempotency key into spans for
        // audit/tracing only — dedupe enforcement is not yet implemented at
        // this layer (see `RuntimeCapabilityRequest::idempotency_key`).
        let idempotency_key = idempotency_key.map(|key| key.as_str().to_string());
        if let Some(key) = idempotency_key.as_deref() {
            tracing::debug!(
                capability_id = %capability_id,
                idempotency_key = %key,
                "capability invocation accepted advisory idempotency key (not yet enforced)"
            );
        }

        // Per-request registry resolution (P1): the plain boot-published
        // snapshot satisfies every floor capability at zero extra cost; only
        // on a miss does this re-discover the caller's per-hire hosted-MCP
        // surface and merge the matching descriptor into a throwaway,
        // per-request clone — never written back to `self.registry`. See
        // `resolve_invocation_registry` for the fail-safe conditions.
        let registry = self
            .resolve_invocation_registry(&scope, &capability_id)
            .await;

        if let Err(error) = self.enforce_runtime_policy(&registry, &capability_id) {
            tracing::debug!(
                capability_id = %capability_id,
                runtime_policy_error_kind = error.kind(),
                "capability runtime policy rejected invocation before dispatch"
            );
            trace_capability_latency_ok(
                "invoke_capability_policy_rejected",
                &capability_id,
                &scope,
                total_started_at,
            );
            return Ok(runtime_policy_failure(capability_id, error));
        }

        let trust_decision = match self.evaluate_invocation_trust(&registry, &capability_id) {
            Ok(host_decision) => host_decision,
            Err(error) => {
                tracing::debug!(
                    capability_id = %capability_id,
                    trust_error_kind = error.kind(),
                    "capability trust evaluation failed before dispatch"
                );
                trace_capability_latency_ok(
                    "invoke_capability_trust_rejected",
                    &capability_id,
                    &scope,
                    total_started_at,
                );
                return Ok(trust_evaluation_failure(capability_id, error));
            }
        };
        context.trust = trust_decision.effective_trust.class();

        // Validate the execution context before the credential pre-flight queries
        // the secret store. Without this guard a malformed RuntimeCapabilityRequest
        // could probe secret-store presence under a forged resource_scope that does
        // not match the top-level tenant/user/agent/project fields.
        if let Err(error) = context.validate() {
            return Err(HostRuntimeError::invalid_request(error.to_string()));
        }

        // Pre-flight credential check: surface AuthRequired BEFORE the approval
        // gate fires. This prevents a human approval being consumed for an action
        // that cannot yet succeed because a required credential is missing.
        //
        // Design note: the pre-flight is trust-class-agnostic by design — it runs
        // before the authorizer and trust/authorization checks. The dispatch-time
        // obligation check (which runs after those checks) is the enforcing layer.
        // The pre-flight provides ordering only (credentials before approval gate).
        let credential_preflight_started_at = live_latency_started_at();
        if let Some(auth_required) = self
            .credential_preflight_check(&capability_id, &scope, &registry)
            .await
        {
            trace_capability_latency_ok(
                "credential_preflight_check",
                &capability_id,
                &scope,
                credential_preflight_started_at,
            );
            trace_capability_latency_ok(
                "invoke_capability_auth_required",
                &capability_id,
                &scope,
                total_started_at,
            );
            return Ok(auth_required);
        }
        trace_capability_latency_ok(
            "credential_preflight_check",
            &capability_id,
            &scope,
            credential_preflight_started_at,
        );

        let approval_started_at = live_latency_started_at();
        self.apply_persistent_approval_policy(
            &mut context,
            &registry,
            PersistentApprovalAction::Dispatch,
            &capability_id,
            &estimate,
            &trust_decision,
        )
        .await;
        trace_capability_latency_ok(
            "persistent_approval_policy",
            &capability_id,
            &scope,
            approval_started_at,
        );
        let host = self.capability_host(&registry);

        let invocation = CapabilityInvocationRequest {
            context,
            capability_id: capability_id.clone(),
            estimate,
            input,
            trust_decision,
        };

        let dispatch_started_at = live_latency_started_at();
        match host.invoke_json(invocation).await {
            Ok(result) => {
                trace_capability_latency_ok(
                    "capability_host_invoke_json",
                    &capability_id,
                    &scope,
                    dispatch_started_at,
                );
                trace_capability_latency_ok(
                    "invoke_capability",
                    &capability_id,
                    &scope,
                    total_started_at,
                );
                Ok(RuntimeCapabilityOutcome::Completed(Box::new(
                    completed_outcome_from(result, capability_id),
                )))
            }
            Err(error) => {
                trace_capability_latency_error(
                    "capability_host_invoke_json",
                    &capability_id,
                    &scope,
                    dispatch_started_at,
                    &error,
                );
                tracing::debug!(
                    capability_id = %capability_id,
                    error_kind = failure_kind_from(&error).as_str(),
                    idempotency_key = idempotency_key.as_deref().unwrap_or(""),
                    "capability invocation failed"
                );
                let translated = self
                    .translate_invocation_error(
                        error,
                        capability_id.clone(),
                        scope.clone(),
                        invocation_id,
                    )
                    .await;
                match &translated {
                    Ok(_) => trace_capability_latency_ok(
                        "invoke_capability",
                        &capability_id,
                        &scope,
                        total_started_at,
                    ),
                    Err(error) => trace_capability_latency_error(
                        "invoke_capability",
                        &capability_id,
                        &scope,
                        total_started_at,
                        error,
                    ),
                }
                translated
            }
        }
    }

    async fn spawn_capability(
        &self,
        request: RuntimeCapabilityRequest,
    ) -> Result<RuntimeCapabilityOutcome, HostRuntimeError> {
        let RuntimeCapabilityRequest {
            mut context,
            capability_id,
            estimate,
            input,
            idempotency_key,
            trust_decision: _caller_trust_decision,
        } = request;
        let input = match host_runtime_spawn_input_for_capability(&capability_id, input)? {
            SpawnInputPreparation::Ready(input) => input,
            SpawnInputPreparation::ModelInputRejected(failure) => {
                tracing::debug!(
                    capability_id = %capability_id,
                    "process sandbox spawn rejected malformed model plan as recoverable tool error"
                );
                return Ok(RuntimeCapabilityOutcome::Failed(failure));
            }
        };
        let scope = context.resource_scope.clone();
        let invocation_id = context.invocation_id;
        let idempotency_key = idempotency_key.map(|key| key.as_str().to_string());
        if let Some(key) = idempotency_key.as_deref() {
            tracing::debug!(
                capability_id = %capability_id,
                idempotency_key = %key,
                "capability spawn accepted advisory idempotency key (not yet enforced)"
            );
        }

        // M1: the spawn/process lane deliberately stays on the PLAIN
        // registry snapshot, never `resolve_invocation_registry`. Discovered
        // hosted-MCP capabilities are `runtime = Mcp`, dispatch-only, and
        // must never become reachable by spawn — see
        // `discovered_hosted_mcp_capability_never_reaches_spawn_lane`.
        let registry = self.registry.snapshot();

        if let Err(error) = self.enforce_runtime_policy(&registry, &capability_id) {
            tracing::debug!(
                capability_id = %capability_id,
                runtime_policy_error_kind = error.kind(),
                "capability runtime policy rejected spawn before process start"
            );
            return Ok(runtime_policy_failure(capability_id, error));
        }

        let trust_decision = match self.evaluate_invocation_trust(&registry, &capability_id) {
            Ok(host_decision) => host_decision,
            Err(error) => {
                tracing::debug!(
                    capability_id = %capability_id,
                    trust_error_kind = error.kind(),
                    "capability trust evaluation failed before spawn"
                );
                return Ok(trust_evaluation_failure(capability_id, error));
            }
        };
        context.trust = trust_decision.effective_trust.class();

        // Validate the execution context before the credential pre-flight queries
        // the secret store. Without this guard a malformed RuntimeCapabilityRequest
        // could probe secret-store presence under a forged resource_scope that does
        // not match the top-level tenant/user/agent/project fields.
        if let Err(error) = context.validate() {
            return Err(HostRuntimeError::invalid_request(error.to_string()));
        }

        // Pre-flight credential check: surface AuthRequired BEFORE the approval
        // gate fires. The pre-flight is trust-class-agnostic by design — the
        // dispatch-time obligation check (which runs after trust/authorization)
        // is the enforcing layer.
        if let Some(auth_required) = self
            .credential_preflight_check(&capability_id, &scope, &registry)
            .await
        {
            return Ok(auth_required);
        }

        self.apply_persistent_approval_policy(
            &mut context,
            &registry,
            PersistentApprovalAction::SpawnCapability,
            &capability_id,
            &estimate,
            &trust_decision,
        )
        .await;
        let host = self.capability_host(&registry);
        let spawn = CapabilitySpawnRequest {
            context,
            capability_id: capability_id.clone(),
            estimate,
            input,
            trust_decision,
        };

        match host.spawn_json(spawn).await {
            Ok(result) => Ok(RuntimeCapabilityOutcome::SpawnedProcess(
                spawned_process_outcome_from(result, capability_id),
            )),
            Err(error) => {
                tracing::debug!(
                    capability_id = %capability_id,
                    error_kind = failure_kind_from(&error).as_str(),
                    idempotency_key = idempotency_key.as_deref().unwrap_or(""),
                    "capability spawn failed"
                );
                self.translate_invocation_error(error, capability_id, scope, invocation_id)
                    .await
            }
        }
    }

    async fn resume_capability(
        &self,
        request: RuntimeCapabilityResumeRequest,
    ) -> Result<RuntimeCapabilityOutcome, HostRuntimeError> {
        let RuntimeCapabilityResumeRequest {
            mut context,
            approval_request_id,
            capability_id,
            estimate,
            input,
            idempotency_key,
            trust_decision: _caller_trust_decision,
        } = request;
        let idempotency_key = idempotency_key.map(|key| key.as_str().to_string());
        if let Some(key) = idempotency_key.as_deref() {
            tracing::debug!(
                capability_id = %capability_id,
                approval_request_id = %approval_request_id,
                idempotency_key = %key,
                "capability resume accepted advisory idempotency key (not yet enforced)"
            );
        }

        // Per-request registry resolution (C1/P1): the approve→resume path
        // IS the success path for a discovered hosted-MCP capability (the
        // invoke-time gate raised precisely because it needed approval).
        // Without re-resolving here, resume dies `UnknownCapability` against
        // the plain registry even though invoke correctly gated it. See
        // `resolve_invocation_registry`.
        let scope = context.resource_scope.clone();
        let registry = self
            .resolve_invocation_registry(&scope, &capability_id)
            .await;

        if let Err(error) = self.enforce_runtime_policy(&registry, &capability_id) {
            tracing::debug!(
                capability_id = %capability_id,
                runtime_policy_error_kind = error.kind(),
                "capability runtime policy rejected resume before dispatch"
            );
            self.fail_matching_blocked_resume_on_preflight_error(
                &context,
                &capability_id,
                approval_request_id,
                error.kind(),
            )
            .await;
            return Ok(runtime_policy_failure(capability_id, error));
        }

        let trust_decision = match self.evaluate_invocation_trust(&registry, &capability_id) {
            Ok(host_decision) => host_decision,
            Err(error) => {
                tracing::debug!(
                    capability_id = %capability_id,
                    trust_error_kind = error.kind(),
                    "capability trust evaluation failed before resume"
                );
                self.fail_matching_blocked_resume_on_preflight_error(
                    &context,
                    &capability_id,
                    approval_request_id,
                    error.kind(),
                )
                .await;
                return Ok(trust_evaluation_failure(capability_id, error));
            }
        };
        context.trust = trust_decision.effective_trust.class();

        let host = self.capability_host(&registry);
        let resume = CapabilityResumeRequest {
            context,
            approval_request_id,
            capability_id: capability_id.clone(),
            estimate,
            input,
            trust_decision,
        };

        match host.resume_json(resume).await {
            Ok(result) => Ok(RuntimeCapabilityOutcome::Completed(Box::new(
                completed_outcome_from(result, capability_id),
            ))),
            // Resume must not start a second approval loop: if the lower layer ever returns
            // AuthorizationRequiresApproval here, surface it as a failed resume instead of
            // translating it back into RuntimeCapabilityOutcome::ApprovalRequired.
            Err(error) => {
                tracing::debug!(
                    capability_id = %capability_id,
                    error_kind = failure_kind_from(&error).as_str(),
                    idempotency_key = idempotency_key.as_deref().unwrap_or(""),
                    "capability resume failed"
                );
                match error {
                    CapabilityInvocationError::AuthorizationRequiresAuth {
                        capability,
                        required_secrets,
                        credential_requirements,
                    } => Ok(auth_required_outcome(
                        capability,
                        required_secrets,
                        credential_requirements,
                    )),
                    other => Ok(RuntimeCapabilityOutcome::Failed(failure_from(
                        other,
                        capability_id,
                    ))),
                }
            }
        }
    }

    async fn auth_resume_capability(
        &self,
        request: RuntimeCapabilityAuthResumeRequest,
    ) -> Result<RuntimeCapabilityOutcome, HostRuntimeError> {
        let RuntimeCapabilityAuthResumeRequest {
            mut context,
            capability_id,
            estimate,
            input,
            idempotency_key,
            trust_decision: _caller_trust_decision,
            approval_request_id,
        } = request;
        let idempotency_key = idempotency_key.map(|key| key.as_str().to_string());
        if let Some(key) = idempotency_key.as_deref() {
            tracing::debug!(
                capability_id = %capability_id,
                approval_request_id = approval_request_id.map(|id| id.to_string()).as_deref().unwrap_or("none"),
                idempotency_key = %key,
                "capability auth-resume accepted advisory idempotency key (not yet enforced)"
            );
        }

        // Per-request registry resolution (C1/P1): see `resume_capability`
        // above — a discovered hosted-MCP capability can equally block on a
        // credential gate (`AuthRequired`) before its approval gate, so
        // auth-resume needs the same per-request merge.
        let scope = context.resource_scope.clone();
        let registry = self
            .resolve_invocation_registry(&scope, &capability_id)
            .await;

        if let Err(error) = self.enforce_runtime_policy(&registry, &capability_id) {
            tracing::debug!(
                capability_id = %capability_id,
                runtime_policy_error_kind = error.kind(),
                "capability runtime policy rejected auth-resume before dispatch"
            );
            self.fail_matching_blocked_auth_resume_on_preflight_error(
                &context,
                &capability_id,
                error.kind(),
            )
            .await;
            return Ok(runtime_policy_failure(capability_id, error));
        }

        let trust_decision = match self.evaluate_invocation_trust(&registry, &capability_id) {
            Ok(host_decision) => host_decision,
            Err(error) => {
                tracing::debug!(
                    capability_id = %capability_id,
                    trust_error_kind = error.kind(),
                    "capability trust evaluation failed before auth-resume"
                );
                self.fail_matching_blocked_auth_resume_on_preflight_error(
                    &context,
                    &capability_id,
                    error.kind(),
                )
                .await;
                return Ok(trust_evaluation_failure(capability_id, error));
            }
        };
        context.trust = trust_decision.effective_trust.class();

        // Re-apply the persistent-approval grant on the auth-resume preflight,
        // mirroring `dispatch_capability`. The original dispatch injected this
        // grant so the authorizer returned `Allow`; the loop re-dispatches the
        // resume with a freshly built context that does not carry it. Without
        // this, a capability authorized only by a persistent-approval grant
        // (e.g. `extension_activate` under admin-config FirstParty trust) is
        // re-authorized grant-less after the user supplies the missing
        // credential and is denied — so the credential gate resumes only to
        // fail authorization, even though a subsequent fresh dispatch succeeds.
        // The helper is a no-op when no matching policy/grant exists, so
        // capabilities that genuinely require fresh approval are unaffected.
        self.apply_persistent_approval_policy(
            &mut context,
            &registry,
            PersistentApprovalAction::Dispatch,
            &capability_id,
            &estimate,
            &trust_decision,
        )
        .await;
        let host = self.capability_host(&registry);
        let auth_resume = CapabilityAuthResumeRequest {
            context,
            capability_id: capability_id.clone(),
            estimate,
            input,
            trust_decision,
            approval_request_id,
        };

        match host.auth_resume_json(auth_resume).await {
            Ok(result) => Ok(RuntimeCapabilityOutcome::Completed(Box::new(
                completed_outcome_from(result, capability_id),
            ))),
            Err(error) => {
                tracing::debug!(
                    capability_id = %capability_id,
                    error_kind = failure_kind_from(&error).as_str(),
                    idempotency_key = idempotency_key.as_deref().unwrap_or(""),
                    "capability auth-resume failed"
                );
                match error {
                    CapabilityInvocationError::AuthorizationRequiresAuth {
                        capability,
                        required_secrets,
                        credential_requirements,
                    } => Ok(auth_required_outcome(
                        capability,
                        required_secrets,
                        credential_requirements,
                    )),
                    other => Ok(RuntimeCapabilityOutcome::Failed(failure_from(
                        other,
                        capability_id,
                    ))),
                }
            }
        }
    }

    async fn resume_spawn_capability(
        &self,
        request: RuntimeCapabilityResumeRequest,
    ) -> Result<RuntimeCapabilityOutcome, HostRuntimeError> {
        let RuntimeCapabilityResumeRequest {
            mut context,
            approval_request_id,
            capability_id,
            estimate,
            input,
            idempotency_key,
            trust_decision: _caller_trust_decision,
        } = request;
        let input = match host_runtime_spawn_input_for_capability(&capability_id, input)? {
            SpawnInputPreparation::Ready(input) => input,
            SpawnInputPreparation::ModelInputRejected(failure) => {
                tracing::debug!(
                    capability_id = %capability_id,
                    "process sandbox spawn resume rejected malformed model plan as recoverable tool error"
                );
                return Ok(RuntimeCapabilityOutcome::Failed(failure));
            }
        };
        let idempotency_key = idempotency_key.map(|key| key.as_str().to_string());
        if let Some(key) = idempotency_key.as_deref() {
            tracing::debug!(
                capability_id = %capability_id,
                approval_request_id = %approval_request_id,
                idempotency_key = %key,
                "capability spawn resume accepted advisory idempotency key (not yet enforced)"
            );
        }

        // M1: plain registry, matching `spawn_capability` — the spawn/process
        // lane never resolves a discovered hosted-MCP capability.
        let registry = self.registry.snapshot();

        if let Err(error) = self.enforce_runtime_policy(&registry, &capability_id) {
            tracing::debug!(
                capability_id = %capability_id,
                runtime_policy_error_kind = error.kind(),
                "capability runtime policy rejected spawn resume before process start"
            );
            self.fail_matching_blocked_resume_on_preflight_error(
                &context,
                &capability_id,
                approval_request_id,
                error.kind(),
            )
            .await;
            return Ok(runtime_policy_failure(capability_id, error));
        }

        let trust_decision = match self.evaluate_invocation_trust(&registry, &capability_id) {
            Ok(host_decision) => host_decision,
            Err(error) => {
                tracing::debug!(
                    capability_id = %capability_id,
                    trust_error_kind = error.kind(),
                    "capability trust evaluation failed before spawn resume"
                );
                self.fail_matching_blocked_resume_on_preflight_error(
                    &context,
                    &capability_id,
                    approval_request_id,
                    error.kind(),
                )
                .await;
                return Ok(trust_evaluation_failure(capability_id, error));
            }
        };
        context.trust = trust_decision.effective_trust.class();

        let host = self.capability_host(&registry);
        let resume = CapabilityResumeRequest {
            context,
            approval_request_id,
            capability_id: capability_id.clone(),
            estimate,
            input,
            trust_decision,
        };

        match host.resume_spawn_json(resume).await {
            Ok(result) => Ok(RuntimeCapabilityOutcome::SpawnedProcess(
                spawned_process_outcome_from(result, capability_id),
            )),
            Err(error) => {
                tracing::debug!(
                    capability_id = %capability_id,
                    error_kind = failure_kind_from(&error).as_str(),
                    idempotency_key = idempotency_key.as_deref().unwrap_or(""),
                    "capability spawn resume failed"
                );
                // Mirror resume_capability: AuthorizationRequiresAuth must return
                // AuthRequired, not Failed. Without this arm a spawned capability
                // that needs re-auth after an approval resume silently fails.
                match error {
                    CapabilityInvocationError::AuthorizationRequiresAuth {
                        capability,
                        required_secrets,
                        credential_requirements,
                    } => Ok(auth_required_outcome(
                        capability,
                        required_secrets,
                        credential_requirements,
                    )),
                    other => Ok(RuntimeCapabilityOutcome::Failed(failure_from(
                        other,
                        capability_id,
                    ))),
                }
            }
        }
    }

    async fn visible_capabilities(
        &self,
        request: VisibleCapabilityRequest,
    ) -> Result<VisibleCapabilitySurface, HostRuntimeError> {
        let registry = self.registry.snapshot();
        let catalog = CapabilityCatalog::new(
            &registry,
            self.authorizer.as_ref(),
            &self.surface_version,
            &self.runtime_policy,
        );
        let catalog = match self.surface_filesystem.as_deref() {
            Some(filesystem) => catalog.with_filesystem(filesystem),
            None => catalog,
        };
        let catalog = match self.hosted_mcp_overlay.as_deref() {
            Some(overlay) => catalog.with_hosted_mcp_overlay(overlay),
            None => catalog,
        };
        catalog.visible_capabilities(request).await
    }

    /// Best-effort cancellation fanout for active work in one scope.
    ///
    /// Background processes can be terminalized through the process store and
    /// cooperative cancellation registry. Inline capability invocations do not
    /// yet expose a cancellation token through [`CapabilityHost`], so active
    /// invocation records are returned as `unsupported` instead of silently
    /// disappearing behind an empty outcome.
    async fn cancel_work(
        &self,
        request: CancelRuntimeWorkRequest,
    ) -> Result<CancelRuntimeWorkOutcome, HostRuntimeError> {
        tracing::debug!(
            correlation_id = %request.correlation_id,
            reason = ?request.reason,
            "host runtime cancellation requested"
        );

        let mut outcome = CancelRuntimeWorkOutcome::default();
        let mut process_invocations = Vec::new();

        if let Some(process_store) = &self.process_store {
            let records = process_store
                .records_for_scope(&request.scope)
                .await
                .map_err(unavailable_from_process_error)?;
            let mut process_host = ProcessHost::new(process_store.as_ref());
            if let Some(registry) = &self.process_cancellation_registry {
                process_host = process_host.with_cancellation_registry(Arc::clone(registry));
            }
            if let Some(result_store) = &self.process_result_store {
                process_host = process_host.with_result_store_dyn(Arc::clone(result_store));
            }

            for record in records {
                if record.status != ProcessStatus::Running {
                    continue;
                }
                process_invocations.push(record.invocation_id);
                let work_id = RuntimeWorkId::Process(record.process_id);
                match process_host.kill(&request.scope, record.process_id).await {
                    Ok(_) => {
                        outcome.cancelled.push(work_id);
                    }
                    Err(ProcessError::InvalidTransition { .. }) => {
                        outcome.already_terminal.push(work_id);
                    }
                    Err(error) => return Err(unavailable_from_process_error(error)),
                }
            }
        }

        if let Some(run_state) = &self.run_state {
            let records = run_state
                .records_for_scope(&request.scope)
                .await
                .map_err(unavailable_from_run_state)?;
            outcome.unsupported.extend(
                records
                    .into_iter()
                    .filter(|record| record.status == RunStatus::Running)
                    .filter(|record| !process_invocations.contains(&record.invocation_id))
                    .map(|record| RuntimeWorkId::Invocation(record.invocation_id)),
            );
        }

        Ok(outcome)
    }

    /// Snapshot of active host runtime work for one scope.
    ///
    /// `correlation_id` is carried for tracing/audit only — at this layer we
    /// surface every running invocation in scope rather than narrowing to the
    /// caller's correlation. Upper turn/loop services that need per-correlation
    /// fan-in are expected to filter the returned summaries themselves.
    async fn runtime_status(
        &self,
        request: RuntimeStatusRequest,
    ) -> Result<HostRuntimeStatus, HostRuntimeError> {
        let mut active_work = Vec::new();
        let registry = self.registry.snapshot();

        if let Some(run_state) = &self.run_state {
            let records = run_state
                .records_for_scope(&request.scope)
                .await
                .map_err(unavailable_from_run_state)?;

            active_work.extend(
                records
                    .into_iter()
                    .filter(|record| record.status == RunStatus::Running)
                    .map(|record| {
                        let runtime = registry
                            .get_capability(&record.capability_id)
                            .map(|descriptor| descriptor.runtime);
                        RuntimeWorkSummary {
                            work_id: RuntimeWorkId::Invocation(record.invocation_id),
                            capability_id: Some(record.capability_id),
                            runtime,
                        }
                    }),
            );
        }

        if let Some(process_store) = &self.process_store {
            let records = process_store
                .records_for_scope(&request.scope)
                .await
                .map_err(unavailable_from_process_error)?;
            let mut process_invocations = Vec::new();
            active_work.extend(
                records
                    .into_iter()
                    .filter(|record| record.status == ProcessStatus::Running)
                    .map(|record| {
                        process_invocations.push(record.invocation_id);
                        RuntimeWorkSummary {
                            work_id: RuntimeWorkId::Process(record.process_id),
                            capability_id: Some(record.capability_id),
                            runtime: Some(record.runtime),
                        }
                    }),
            );
            if !process_invocations.is_empty() {
                active_work.retain(|summary| match &summary.work_id {
                    RuntimeWorkId::Invocation(invocation_id) => {
                        !process_invocations.contains(invocation_id)
                    }
                    RuntimeWorkId::Process(_) | RuntimeWorkId::Gate(_) => true,
                });
            }
        }

        Ok(HostRuntimeStatus { active_work })
    }

    /// Returns readiness for runtime backends required by registered capabilities.
    async fn health(&self) -> Result<HostRuntimeHealth, HostRuntimeError> {
        let registry = self.registry.snapshot();
        let required = required_runtime_backends(&registry);
        if required.is_empty() {
            return Ok(HostRuntimeHealth {
                ready: true,
                missing_runtime_backends: Vec::new(),
            });
        }

        let missing_runtime_backends = if let Some(health) = &self.runtime_health {
            let reported = health.missing_runtime_backends(&required).await?;
            normalize_missing_runtime_backends(&required, reported)
        } else {
            required
        };
        Ok(HostRuntimeHealth {
            ready: missing_runtime_backends.is_empty(),
            missing_runtime_backends,
        })
    }
}

impl DefaultHostRuntime {
    fn capability_host<'a>(
        &'a self,
        registry: &'a ExtensionRegistry,
    ) -> CapabilityHost<'a, dyn CapabilityDispatcher> {
        let mut host =
            CapabilityHost::new(registry, self.dispatcher.as_ref(), self.authorizer.as_ref());
        if let Some(run_state_approval_store) = &self.run_state_approval_store {
            host = host.with_run_state_approval_store(run_state_approval_store.as_ref());
        } else {
            if let Some(run_state) = &self.run_state {
                host = host.with_run_state(run_state.as_ref());
            }
            if let Some(approval_requests) = &self.approval_requests {
                host = host.with_approval_requests(approval_requests.as_ref());
            }
        }
        if let Some(capability_leases) = &self.capability_leases {
            host = host.with_capability_leases(capability_leases.as_ref());
        }
        if let Some(process_manager) = &self.process_manager {
            host = host.with_process_manager(process_manager.as_ref());
        }
        if let Some(obligation_handler) = &self.obligation_handler {
            host = host.with_obligation_handler(obligation_handler.as_ref());
        }
        host
    }

    /// Resolves the [`ExtensionRegistry`] snapshot used for one dispatch
    /// entrypoint (invoke, resume, auth-resume). The plain boot-published
    /// registry snapshot satisfies every floor capability at zero extra
    /// cost — only an `Arc` refcount bump, never a struct clone. Only on a
    /// registry MISS — and only when the scope carries an `agent_id`
    /// (`HireScope::from_scope`) and a hosted-MCP overlay is attached —
    /// this re-discovers the caller's per-hire hosted-MCP surface and
    /// merges the matching descriptor into a PER-REQUEST clone. That clone
    /// is never written back to `self.registry` (the shared boot
    /// registry): each call gets its own throwaway `ExtensionRegistry`, so
    /// a discovered capability is resolvable for this dispatch only, never
    /// leaks across tenants, and never touches the global registry commit
    /// path.
    ///
    /// Fail-safe: overlay absent, scope has no `agent_id`, discovery times
    /// out/errors, no discovered descriptor matches `capability_id`, or the
    /// merge itself fails consistency validation — all fall through to the
    /// unchanged plain snapshot, i.e. the existing `UnknownCapability` path.
    /// Deliberately NOT called from the spawn/resume-spawn lane (M1):
    /// discovered hosted-MCP capabilities are `runtime = Mcp`,
    /// dispatch-only, and must stay unreachable by spawn.
    async fn resolve_invocation_registry(
        &self,
        scope: &ResourceScope,
        capability_id: &CapabilityId,
    ) -> Arc<ExtensionRegistry> {
        let registry = self.registry.snapshot();
        if registry.get_capability(capability_id).is_some() {
            return registry;
        }
        let Some(overlay) = self.hosted_mcp_overlay.as_deref() else {
            return registry;
        };
        let Some(hire) = crate::HireScope::from_scope(scope) else {
            return registry;
        };
        let discovered =
            crate::discover_overlay_capabilities_for_hire(&registry, overlay, &hire).await;
        let Some(descriptor) = discovered
            .into_iter()
            .find(|descriptor| &descriptor.id == capability_id)
        else {
            return registry;
        };
        match registry.merge_discovered_capability(descriptor) {
            Ok(merged) => Arc::new(merged),
            Err(error) => {
                tracing::debug!(
                    capability_id = %capability_id,
                    error = %error,
                    "discovered hosted-MCP capability could not be merged into the per-request registry"
                );
                registry
            }
        }
    }

    fn evaluate_invocation_trust(
        &self,
        registry: &ExtensionRegistry,
        capability_id: &CapabilityId,
    ) -> Result<TrustDecision, TrustEvaluationError> {
        let policy = self.trust_policy.as_ref();

        let descriptor = registry
            .get_capability(capability_id)
            .ok_or(TrustEvaluationError::UnknownCapability)?;
        let package = registry
            .get_extension(&descriptor.provider)
            .ok_or(TrustEvaluationError::MissingPackage)?;
        let package_descriptor = package
            .capabilities
            .iter()
            .find(|candidate| candidate.id == *capability_id)
            .ok_or(TrustEvaluationError::StalePackageDescriptor)?;
        if package_descriptor != descriptor {
            return Err(TrustEvaluationError::ConflictingPackageDescriptor);
        }

        let input = trust_policy_input_for_local_manifest(package)?;
        let decision = match policy.evaluate(&input) {
            Ok(decision) => decision,
            Err(error) => {
                tracing::debug!(
                    capability_id = %capability_id,
                    trust_policy_error_kind = trust_error_label(&error),
                    "host trust policy evaluation returned an error"
                );
                return Err(TrustEvaluationError::Policy);
            }
        };
        trace_trust_decision(capability_id, &decision);
        Ok(decision)
    }

    fn enforce_runtime_policy(
        &self,
        registry: &ExtensionRegistry,
        capability_id: &CapabilityId,
    ) -> Result<(), RuntimePolicyEvaluationError> {
        let descriptor = registry
            .get_capability(capability_id)
            .ok_or(RuntimePolicyEvaluationError::UnknownCapability)?;
        let plan = plan_capability(descriptor, &self.runtime_policy)
            .map_err(RuntimePolicyEvaluationError::Denied)?;
        tracing::debug!(
            capability_id = %capability_id,
            filesystem_backend = ?plan.filesystem_backend,
            process_backend = ?plan.process_backend,
            network_mode = ?plan.network_mode,
            secret_mode = ?plan.secret_mode,
            "capability runtime policy planned invocation"
        );
        Ok(())
    }

    async fn apply_persistent_approval_policy(
        &self,
        context: &mut ironclaw_host_api::ExecutionContext,
        registry: &ExtensionRegistry,
        action: PersistentApprovalAction,
        capability_id: &CapabilityId,
        estimate: &ResourceEstimate,
        trust_decision: &TrustDecision,
    ) {
        let Some(policies) = self.persistent_approval_policies.as_ref() else {
            return;
        };
        let Some(descriptor) = registry.get_capability(capability_id) else {
            return;
        };
        if !permission_mode_allows_persistent_approval(descriptor.default_permission) {
            tracing::debug!(
                capability_id = %capability_id,
                permission = ?descriptor.default_permission,
                "persistent approval skipped for manifest policy"
            );
            return;
        }
        let scopes = persistent_approval_lookup_scopes(&context.resource_scope);
        let grantees = persistent_approval_grantees(context);
        let lookup_results = join_all(
            scopes
                .into_iter()
                .flat_map(|scope| {
                    grantees
                        .iter()
                        .cloned()
                        .map(move |grantee| (scope.clone(), grantee))
                })
                .map(|(scope, grantee)| {
                    let policies = Arc::clone(policies);
                    let key = PersistentApprovalPolicyKey {
                        scope,
                        action,
                        capability_id: capability_id.clone(),
                        grantee,
                    };
                    async move { policies.lookup(&key).await }
                }),
        )
        .await;
        for policy in lookup_results {
            let policy = match policy {
                Ok(policy) => policy,
                Err(error) => {
                    tracing::warn!(
                        capability_id = %capability_id,
                        error = %error,
                        "persistent approval policy lookup failed; falling back to normal authorization"
                    );
                    continue;
                }
            };
            let Some(policy) = policy else {
                continue;
            };
            let Some(grant) = policy.active_grant() else {
                continue;
            };
            let mut candidate_context = context.clone();
            candidate_context.grants.grants.clear();
            candidate_context.grants.grants.push(grant.clone());
            let decision = match action {
                PersistentApprovalAction::Dispatch => {
                    self.authorizer
                        .authorize_dispatch_with_trust(
                            &candidate_context,
                            descriptor,
                            estimate,
                            trust_decision,
                        )
                        .await
                }
                PersistentApprovalAction::SpawnCapability => {
                    self.authorizer
                        .authorize_spawn_with_trust(
                            &candidate_context,
                            descriptor,
                            estimate,
                            trust_decision,
                        )
                        .await
                }
            };
            match decision {
                Decision::Allow { .. } => {}
                Decision::Deny { reason } => {
                    tracing::debug!(
                        capability_id = %capability_id,
                        deny_reason = ?reason,
                        "persistent approval policy matched but cannot authorize invocation"
                    );
                    continue;
                }
                Decision::RequireApproval { .. } => {
                    tracing::debug!(
                        capability_id = %capability_id,
                        "persistent approval policy matched but still requires approval"
                    );
                    continue;
                }
            }
            tracing::debug!(
                capability_id = %capability_id,
                "persistent approval policy matched; injecting scoped grant"
            );
            context.grants.grants.push(grant);
            break;
        }
    }

    async fn fail_matching_blocked_resume_on_preflight_error(
        &self,
        context: &ironclaw_host_api::ExecutionContext,
        capability_id: &CapabilityId,
        approval_request_id: ApprovalRequestId,
        error_kind: &'static str,
    ) {
        if context.validate().is_err() {
            return;
        }
        let Some(run_state) = self.run_state.as_ref() else {
            return;
        };
        let scope = &context.resource_scope;
        let invocation_id = context.invocation_id;
        let record = match run_state.get(scope, invocation_id).await {
            Ok(Some(record)) => record,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(
                    invocation_id = %invocation_id,
                    capability_id = %capability_id,
                    preflight_error_kind = error_kind,
                    transition_error = %unavailable_from_run_state(error),
                    "blocked resume preflight failed, but run-state lookup failed; leaving run state unchanged",
                );
                return;
            }
        };
        if record.status != RunStatus::BlockedApproval
            || &record.capability_id != capability_id
            || record.approval_request_id != Some(approval_request_id)
        {
            return;
        }
        if let Err(error) = run_state
            .fail(scope, invocation_id, error_kind.to_string())
            .await
        {
            tracing::warn!(
                invocation_id = %invocation_id,
                capability_id = %capability_id,
                approval_request_id = %approval_request_id,
                preflight_error_kind = error_kind,
                transition_error = %unavailable_from_run_state(error),
                "blocked resume preflight failed, but run-state fail transition failed; original failure is returned to caller",
            );
        }
    }

    /// Mirrors `fail_matching_blocked_resume_on_preflight_error` for
    /// `auth_resume_capability` preflight rejections.  Checks for a
    /// `BlockedAuth` run record matching the capability; if found,
    /// transitions it to `Failed` so it is not left as a stale resumable
    /// gate after the caller has returned a terminal failure outcome.
    ///
    /// The `approval_request_id` carried by the auth-resume request is
    /// intentionally NOT compared here: the `BlockedAuth` transition always
    /// clears `approval_request_id` to `None` on the persisted record, so
    /// any equality check against `Some(id)` would always fail and silently
    /// skip the fail-transition.  `invocation_id` (embedded in `context`)
    /// already uniquely identifies the run.
    async fn fail_matching_blocked_auth_resume_on_preflight_error(
        &self,
        context: &ironclaw_host_api::ExecutionContext,
        capability_id: &CapabilityId,
        error_kind: &'static str,
    ) {
        if context.validate().is_err() {
            return;
        }
        let Some(run_state) = self.run_state.as_ref() else {
            return;
        };
        let scope = &context.resource_scope;
        let invocation_id = context.invocation_id;
        let record = match run_state.get(scope, invocation_id).await {
            Ok(Some(record)) => record,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(
                    invocation_id = %invocation_id,
                    capability_id = %capability_id,
                    preflight_error_kind = error_kind,
                    transition_error = %unavailable_from_run_state(error),
                    "blocked auth-resume preflight failed, but run-state lookup failed; leaving run state unchanged",
                );
                return;
            }
        };
        if record.status != RunStatus::BlockedAuth || &record.capability_id != capability_id {
            return;
        }
        if let Err(error) = run_state
            .fail(scope, invocation_id, error_kind.to_string())
            .await
        {
            tracing::warn!(
                invocation_id = %invocation_id,
                capability_id = %capability_id,
                preflight_error_kind = error_kind,
                transition_error = %unavailable_from_run_state(error),
                "blocked auth-resume preflight failed, but run-state fail transition failed; original failure is returned to caller",
            );
        }
    }

    async fn translate_invocation_error(
        &self,
        error: CapabilityInvocationError,
        capability_id: CapabilityId,
        scope: ResourceScope,
        invocation_id: InvocationId,
    ) -> Result<RuntimeCapabilityOutcome, HostRuntimeError> {
        match error {
            CapabilityInvocationError::AuthorizationRequiresApproval { capability } => {
                match self.lookup_approval_request_id(&scope, invocation_id).await {
                    Ok(Some(approval_request_id)) => Ok(
                        RuntimeCapabilityOutcome::ApprovalRequired(RuntimeApprovalGate {
                            approval_request_id,
                            capability_id: capability,
                            reason: RuntimeBlockedReason::ApprovalRequired,
                        }),
                    ),
                    Ok(None) => Ok(RuntimeCapabilityOutcome::Failed(
                        RuntimeCapabilityFailure::new(
                            capability,
                            RuntimeFailureKind::Authorization,
                            Some(
                                "approval required but no approval request was persisted"
                                    .to_string(),
                            ),
                        ),
                    )),
                    Err(host_error) => {
                        // Surface persistence outages as Unavailable rather than
                        // pretending the approval was never persisted; otherwise a
                        // transient run-state failure looks indistinguishable from
                        // the (separately bug-prone) cap-host-skipped-persist path.
                        tracing::warn!(
                            capability_id = %capability,
                            error = %host_error,
                            "approval request lookup failed; surfacing as host runtime unavailability"
                        );
                        Err(host_error)
                    }
                }
            }
            CapabilityInvocationError::AuthorizationRequiresAuth {
                capability,
                required_secrets,
                credential_requirements,
            } => Ok(auth_required_outcome(
                capability,
                required_secrets,
                credential_requirements,
            )),
            other => {
                let should_fail_dispatch_run =
                    matches!(other, CapabilityInvocationError::Dispatch { .. });
                let failure = failure_from(other, capability_id);
                if should_fail_dispatch_run {
                    self.fail_dispatch_run(&failure, &scope, invocation_id)
                        .await;
                }
                Ok(RuntimeCapabilityOutcome::Failed(failure))
            }
        }
    }

    async fn fail_dispatch_run(
        &self,
        failure: &RuntimeCapabilityFailure,
        scope: &ResourceScope,
        invocation_id: InvocationId,
    ) {
        let Some(run_state) = self.run_state.as_ref() else {
            return;
        };
        if let Err(error) = run_state
            .fail(scope, invocation_id, "Dispatch".to_string())
            .await
        {
            tracing::warn!(
                invocation_id = %invocation_id,
                capability_id = %failure.capability_id,
                failure_kind = failure.kind.as_str(),
                transition_error = %unavailable_from_run_state(error),
                "terminal dispatch failure could not transition run state; failure is returned to caller",
            );
        }
    }

    async fn lookup_approval_request_id(
        &self,
        scope: &ResourceScope,
        invocation_id: InvocationId,
    ) -> Result<Option<ApprovalRequestId>, HostRuntimeError> {
        let Some(run_state) = self.run_state.as_ref() else {
            return Ok(None);
        };
        let record = run_state
            .get(scope, invocation_id)
            .await
            .map_err(unavailable_from_run_state)?;
        Ok(record.and_then(|record| record.approval_request_id))
    }

    /// Checks whether all required credentials declared in the capability
    /// manifest are present in the secret store.
    ///
    /// `registry` is the already-snapshotted registry from the caller; the
    /// caller is responsible for taking a single snapshot and passing it here
    /// to avoid a redundant `registry.snapshot()` inside this method.
    ///
    /// Returns `Some(RuntimeCapabilityOutcome::AuthRequired)` if any required
    /// secret is absent, or `None` when all secrets are present (or when no
    /// secret store is wired, i.e. pre-flight is disabled).
    ///
    /// The dispatch-time obligation check remains the enforcement backstop —
    /// this method provides ordering only (credentials before approval gate).
    ///
    /// ## Failure handling
    ///
    /// On a transient secret-store `Err`, the pre-flight is skipped entirely
    /// (returns `None`) rather than treating the error as "credential absent"
    /// and firing `AuthRequired`. A backend failure must not burn a user auth
    /// interaction — the dispatch-time obligation check enforces the credential
    /// requirement and will catch genuine absences at execution time.
    async fn credential_preflight_check(
        &self,
        capability_id: &CapabilityId,
        scope: &ResourceScope,
        registry: &ExtensionRegistry,
    ) -> Option<RuntimeCapabilityOutcome> {
        let secret_store = self.credential_preflight_store.as_ref()?;

        let descriptor = registry.get_capability(capability_id)?;

        let (required_secrets, credential_requirements) =
            capability_credential_requirements(descriptor);

        if required_secrets.is_empty() {
            return None;
        }

        for handle in &required_secrets {
            // `secret_present` is the single owner of the presence rule, shared with
            // the dispatch-time obligation backstop (obligations::preflight_secret_injection)
            // so the two paths cannot drift on "what counts as a present credential".
            // The happy path intentionally re-checks at dispatch time; this pre-flight
            // read is only for gate ordering. (Accepted double-read; the backstop is the
            // authority — see the thread on collapsing it.)
            match secret_present(secret_store.as_ref(), scope, handle).await {
                Ok(true) => {
                    // Secret present — continue checking.
                }
                Ok(false) => {
                    tracing::debug!(
                        capability_id = %capability_id,
                        secret_handle = handle.as_str(),
                        "credential pre-flight: required secret absent; surfacing AuthRequired before approval gate"
                    );
                    return Some(auth_required_outcome(
                        capability_id.clone(),
                        required_secrets,
                        credential_requirements,
                    ));
                }
                Err(error) => {
                    // Fail-open: a transient store error must not masquerade as a
                    // missing credential and burn a user auth interaction. Skip the
                    // pre-flight entirely — the dispatch-time obligation check is the
                    // enforcement backstop and will catch genuine absences at execution
                    // time. The cause is logged (sanitized; SecretStoreError carries no
                    // raw secret material) so a backend outage still leaves a trail.
                    tracing::debug!(
                        capability_id = %capability_id,
                        secret_handle = handle.as_str(),
                        error = %error,
                        "credential pre-flight: secret store metadata query failed; skipping pre-flight (dispatch-time check enforces)"
                    );
                    return None; // silent-ok: transient store error must not burn a user auth interaction; dispatch-time obligation check is the backstop
                }
            }
        }

        None
    }
}

#[derive(Debug, Clone, Copy)]
enum TrustEvaluationError {
    UnknownCapability,
    MissingPackage,
    StalePackageDescriptor,
    ConflictingPackageDescriptor,
    TrustInput,
    Policy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RuntimePolicyEvaluationError {
    UnknownCapability,
    Denied(crate::PlannerError),
}

impl RuntimePolicyEvaluationError {
    fn kind(&self) -> &'static str {
        match self {
            Self::UnknownCapability => "unknown_capability",
            Self::Denied(crate::PlannerError::ProcessEffectsRequiredButProcessBackendIsNone {
                ..
            }) => "process_backend_none",
            Self::Denied(crate::PlannerError::NetworkRequiredButNetworkModeIsDeny { .. }) => {
                "network_denied"
            }
            Self::Denied(crate::PlannerError::SecretAccessRequiredButSecretModeIsDeny {
                ..
            }) => "secret_denied",
        }
    }

    fn message(&self) -> String {
        match self {
            Self::UnknownCapability => "unknown capability".to_string(),
            Self::Denied(error) => format!("runtime policy denied capability: {error}"),
        }
    }
}

impl TrustEvaluationError {
    const fn kind(self) -> &'static str {
        match self {
            Self::UnknownCapability => "unknown_capability",
            Self::MissingPackage => "missing_package",
            Self::StalePackageDescriptor => "stale_package_descriptor",
            Self::ConflictingPackageDescriptor => "conflicting_package_descriptor",
            Self::TrustInput => "trust_input",
            Self::Policy => "policy",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::UnknownCapability => "unknown capability",
            Self::MissingPackage => "capability provider trust metadata is missing",
            Self::StalePackageDescriptor | Self::ConflictingPackageDescriptor => {
                "capability provider trust metadata is stale"
            }
            Self::TrustInput => "capability provider trust metadata is invalid",
            Self::Policy => "capability provider trust policy evaluation failed",
        }
    }
}

fn trust_policy_input_for_local_manifest(
    package: &ExtensionPackage,
) -> Result<ironclaw_trust::TrustPolicyInput, TrustEvaluationError> {
    package
        .trust_policy_input(
            local_manifest_source(package),
            package.manifest_digest(),
            None,
        )
        .map_err(|_| TrustEvaluationError::TrustInput)
}

fn local_manifest_source(package: &ExtensionPackage) -> PackageSource {
    PackageSource::LocalManifest {
        path: format!(
            "{}/manifest.toml",
            package.root.as_str().trim_end_matches('/')
        ),
    }
}

fn trace_trust_decision(capability_id: &CapabilityId, decision: &TrustDecision) {
    tracing::debug!(
        capability_id = %capability_id,
        effective_trust = ?decision.effective_trust.class(),
        trust_provenance = trust_provenance_label(&decision.provenance),
        trust_allowed_effect_count = decision.authority_ceiling.allowed_effects.len(),
        trust_has_resource_ceiling = decision.authority_ceiling.max_resource_ceiling.is_some(),
        "evaluated capability provider trust from host policy"
    );
}

fn trust_provenance_label(provenance: &TrustProvenance) -> &'static str {
    match provenance {
        TrustProvenance::Default => "default",
        TrustProvenance::Bundled => "bundled",
        TrustProvenance::AdminConfig => "admin_config",
        TrustProvenance::SignedRegistry { .. } => "signed_registry",
        TrustProvenance::LocalManifest => "local_manifest",
    }
}

fn trust_error_label(error: &TrustError) -> &'static str {
    match error {
        TrustError::InvariantViolation { .. } => "invariant_violation",
    }
}

fn trust_evaluation_failure(
    capability_id: CapabilityId,
    error: TrustEvaluationError,
) -> RuntimeCapabilityOutcome {
    RuntimeCapabilityOutcome::Failed(RuntimeCapabilityFailure::new(
        capability_id,
        trust_evaluation_failure_kind(error),
        Some(error.message().to_string()),
    ))
}

fn runtime_policy_failure(
    capability_id: CapabilityId,
    error: RuntimePolicyEvaluationError,
) -> RuntimeCapabilityOutcome {
    RuntimeCapabilityOutcome::Failed(RuntimeCapabilityFailure::new(
        capability_id,
        runtime_policy_failure_kind(&error),
        Some(error.message()),
    ))
}

fn runtime_policy_failure_kind(error: &RuntimePolicyEvaluationError) -> RuntimeFailureKind {
    match error {
        RuntimePolicyEvaluationError::UnknownCapability => RuntimeFailureKind::MissingRuntime,
        RuntimePolicyEvaluationError::Denied(_) => RuntimeFailureKind::Authorization,
    }
}

fn trust_evaluation_failure_kind(error: TrustEvaluationError) -> RuntimeFailureKind {
    match error {
        TrustEvaluationError::UnknownCapability => RuntimeFailureKind::MissingRuntime,
        TrustEvaluationError::MissingPackage
        | TrustEvaluationError::StalePackageDescriptor
        | TrustEvaluationError::ConflictingPackageDescriptor
        | TrustEvaluationError::TrustInput
        | TrustEvaluationError::Policy => RuntimeFailureKind::Authorization,
    }
}

/// Maps a [`RunStateError`] to a sanitized [`HostRuntimeError::Unavailable`].
///
/// `RunStateError::InvalidPath` and `Filesystem` carry raw filesystem
/// strings; `Serialization`/`Deserialization` carry serde internals. Forward
/// the redacted variant discriminator instead of `error.to_string()` so the
/// boundary stays infrastructure-opaque to upper services.
fn unavailable_from_run_state(error: RunStateError) -> HostRuntimeError {
    let reason = match error {
        RunStateError::UnknownInvocation { .. } => "run-state record not found",
        RunStateError::InvocationAlreadyExists { .. } => "run-state record already exists",
        RunStateError::UnknownApprovalRequest { .. } => "approval request not found",
        RunStateError::ApprovalRequestAlreadyExists { .. } => "approval request already exists",
        RunStateError::ApprovalNotPending { .. } => "approval request not pending",
        RunStateError::InvalidPath(_) => "run-state storage path invalid",
        RunStateError::Filesystem(_) => "run-state filesystem unavailable",
        RunStateError::Serialization(_) => "run-state serialization failed",
        RunStateError::Deserialization(_) => "run-state deserialization failed",
        RunStateError::Backend(_) => "run-state backend unavailable",
    };
    HostRuntimeError::unavailable(reason)
}

/// Maps a [`ProcessError`] to a sanitized [`HostRuntimeError::Unavailable`].
fn unavailable_from_process_error(error: ProcessError) -> HostRuntimeError {
    let reason = match error {
        ProcessError::UnknownProcess { .. } => "process record not found",
        ProcessError::ProcessAlreadyExists { .. } => "process record already exists",
        ProcessError::InvalidTransition { .. } => "process lifecycle transition invalid",
        ProcessError::ResourceReservationMismatch { .. } => "process resource reservation mismatch",
        ProcessError::ResourceReservationAlreadyAssigned { .. } => {
            "process resource reservation already assigned"
        }
        ProcessError::ResourceReservationNotOwned { .. } => {
            "process resource reservation not owned"
        }
        ProcessError::Resource(_) => "process resource lifecycle failed",
        ProcessError::ResourceCleanupFailed { .. } => "process resource cleanup failed",
        ProcessError::ProcessResultStoreUnavailable => "process result store unavailable",
        ProcessError::ProcessResultUnavailable { .. } => "process result unavailable",
        ProcessError::InvalidStoredRecord { .. } => "process stored record invalid",
        ProcessError::InvalidPath(_) => "process storage path invalid",
        ProcessError::Filesystem(_) => "process filesystem unavailable",
        ProcessError::Serialization(_) => "process serialization failed",
        ProcessError::Deserialization(_) => "process deserialization failed",
    };
    HostRuntimeError::unavailable(reason)
}

fn required_runtime_backends(registry: &ExtensionRegistry) -> Vec<RuntimeKind> {
    let mut required = Vec::new();
    for descriptor in registry.capabilities() {
        if !required.contains(&descriptor.runtime) {
            required.push(descriptor.runtime);
        }
    }
    required.sort_by_key(|runtime| runtime_kind_rank(*runtime));
    required
}

fn normalize_missing_runtime_backends(
    required: &[RuntimeKind],
    reported: Vec<RuntimeKind>,
) -> Vec<RuntimeKind> {
    let mut missing = Vec::new();
    for runtime in reported {
        if required.contains(&runtime) && !missing.contains(&runtime) {
            missing.push(runtime);
        }
    }
    missing.sort_by_key(|runtime| runtime_kind_rank(*runtime));
    missing
}

fn runtime_kind_rank(runtime: RuntimeKind) -> u8 {
    match runtime {
        RuntimeKind::Wasm => 0,
        RuntimeKind::Mcp => 1,
        RuntimeKind::Script => 2,
        RuntimeKind::FirstParty => 3,
        RuntimeKind::System => 4,
    }
}

fn completed_outcome_from(
    result: CapabilityInvocationResult,
    capability_id: CapabilityId,
) -> RuntimeCapabilityCompleted {
    RuntimeCapabilityCompleted {
        capability_id,
        output: result.dispatch.output,
        display_preview: result.dispatch.display_preview,
        usage: result.dispatch.usage,
    }
}

/// Returns the required secrets and OAuth credential requirements declared in
/// the capability descriptor.
///
/// This is the canonical extraction used by the **pre-flight credential
/// presence check** (before the approval gate). The dispatch-time obligation
/// check remains the enforcement backstop; it derives the same handles through
/// the obligation-handler iteration over `descriptor.runtime_credentials`
/// (same source, different code path — both iterate `required == true` entries).
/// The two paths agree on which handles are required; the pre-flight additionally
/// computes `credential_requirements` for the auth-gate payload.
///
/// Callers outside the pre-flight check must not recompute the requirement set
/// independently — call this function instead.
///
/// Only entries with `required == true` **and** `source == SecretHandle` are
/// included in `required_secrets`. `ProductAuthAccount`-source credentials are
/// staged by the credential-account resolver at dispatch time (not via
/// `secret_store.metadata`), so including their slot handle here would produce
/// a false-positive `AuthRequired` for capabilities whose product-auth account
/// is already connected.
pub(crate) fn capability_credential_requirements(
    descriptor: &ironclaw_host_api::CapabilityDescriptor,
) -> (
    Vec<SecretHandle>,
    Vec<ironclaw_host_api::RuntimeCredentialAuthRequirement>,
) {
    let provider = descriptor.provider.clone();
    let mut required_secrets = Vec::new();
    let mut credential_requirements = Vec::new();

    // Double-read accepted: the dispatch-time obligation path (in
    // ironclaw_host_runtime::obligations) will re-check each handle's presence via
    // the same secret_store when the capability executes. Threading the pre-flight
    // result into the obligation path would cross crate-boundary constraints (per
    // CLAUDE.md) without meaningful gain; the ordering guarantee (auth before
    // approval gate) is the pre-flight's sole purpose.
    for cred in &descriptor.runtime_credentials {
        if !cred.required {
            continue;
        }
        // Only SecretHandle-source credentials are presence-checkable in the
        // secret store. ProductAuthAccount credentials are staged by the
        // credential-account resolver at dispatch time (not via secret_store.metadata),
        // so including their slot handle here would produce a false-positive AuthRequired
        // for capabilities whose product-auth account is already connected.
        if matches!(
            cred.source,
            ironclaw_host_api::RuntimeCredentialRequirementSource::SecretHandle
        ) {
            required_secrets.push(cred.handle.clone());
        }
        if let Some(auth_req) = cred.product_auth_requirement_for(provider.clone()) {
            credential_requirements.push(auth_req);
        }
    }
    (required_secrets, credential_requirements)
}

fn auth_required_outcome(
    capability_id: CapabilityId,
    required_secrets: Vec<SecretHandle>,
    credential_requirements: Vec<ironclaw_host_api::RuntimeCredentialAuthRequirement>,
) -> RuntimeCapabilityOutcome {
    RuntimeCapabilityOutcome::AuthRequired(RuntimeAuthGate {
        gate_id: stable_auth_gate_id(&capability_id, &required_secrets, &credential_requirements),
        capability_id,
        reason: RuntimeBlockedReason::AuthRequired,
        required_secrets,
        credential_requirements,
    })
}

fn stable_auth_gate_id(
    capability_id: &CapabilityId,
    required_secrets: &[SecretHandle],
    credential_requirements: &[RuntimeCredentialAuthRequirement],
) -> RuntimeGateId {
    let mut parts = Vec::new();
    parts.push(format!("capability={}", capability_id.as_str()));

    let mut secret_handles = required_secrets
        .iter()
        .map(|handle| handle.as_str().to_string())
        .collect::<Vec<_>>();
    secret_handles.sort();
    for handle in secret_handles {
        parts.push(format!("secret={handle}"));
    }

    let mut requirements = credential_requirements
        .iter()
        .map(|requirement| {
            let mut scopes = requirement.provider_scopes.clone();
            scopes.sort();
            format!(
                "credential={}:{}:{}",
                requirement.provider.as_str(),
                requirement.requester_extension.as_str(),
                scopes.join(",")
            )
        })
        .collect::<Vec<_>>();
    requirements.sort();
    parts.extend(requirements);

    let digest = sha256_digest_token(parts.join("\n").as_bytes());
    let suffix = digest.strip_prefix("sha256:").unwrap_or(&digest);
    RuntimeGateId::from_stable_suffix(&format!("auth-{suffix}"))
        .unwrap_or_else(|_| RuntimeGateId::new())
}

fn spawned_process_outcome_from(
    result: CapabilitySpawnResult,
    capability_id: CapabilityId,
) -> crate::RuntimeProcessHandle {
    crate::RuntimeProcessHandle {
        process_id: result.process.process_id,
        capability_id,
    }
}

fn persistent_approval_grantees(context: &ironclaw_host_api::ExecutionContext) -> Vec<Principal> {
    let mut grantees = vec![
        Principal::Extension(context.extension_id.clone()),
        Principal::User(context.user_id.clone()),
    ];
    if let Some(agent_id) = &context.agent_id {
        grantees.push(Principal::Agent(agent_id.clone()));
    }
    if let Some(project_id) = &context.project_id {
        grantees.push(Principal::Project(project_id.clone()));
    }
    if let Some(mission_id) = &context.mission_id {
        grantees.push(Principal::Mission(mission_id.clone()));
    }
    // No `Principal::Thread` grantee: persistent approval policies are never
    // written under a thread grantee (the grantee always comes from
    // `ApprovalRequest.requested_by`, which is `Principal::User` or
    // `Principal::Extension`), so looking one up could never match. Persistent
    // approvals are deliberately thread-agnostic (see #4825).
    grantees
}

fn persistent_approval_lookup_scopes(scope: &ResourceScope) -> Vec<PersistentApprovalScope> {
    let user_scope = PersistentApprovalScope {
        tenant_id: scope.tenant_id.clone(),
        user_id: scope.user_id.clone(),
        agent_id: None,
        project_id: None,
    };
    let legacy_scope = PersistentApprovalScope::from_resource_scope(scope);
    if legacy_scope == user_scope {
        vec![user_scope]
    } else {
        // User-scope settings-page policies intentionally win lookup order over
        // legacy agent/project-scoped prompt policies.
        vec![user_scope, legacy_scope]
    }
}

/// Outcome of preparing model-supplied spawn input for a capability.
///
/// A malformed or invalid process-sandbox plan is a *model-fixable* condition:
/// the model chose bad arguments and can correct them on a retry. It must
/// surface as a recoverable, model-visible tool error
/// ([`RuntimeFailureKind::InvalidInput`] → `ModelVisibleToolError`), never as a
/// terminal [`HostRuntimeError`] that ends the whole run. Genuine host-side
/// faults (serializing the validated host struct back to JSON) remain errors.
enum SpawnInputPreparation {
    /// Input is ready to dispatch to the capability host.
    Ready(serde_json::Value),
    /// Model supplied an unparseable/invalid plan — recoverable, model-visible.
    ModelInputRejected(RuntimeCapabilityFailure),
}

fn host_runtime_spawn_input_for_capability(
    capability_id: &CapabilityId,
    input: serde_json::Value,
) -> Result<SpawnInputPreparation, HostRuntimeError> {
    if capability_id.as_str() != PROCESS_SANDBOX_CAPABILITY_ID {
        return Ok(SpawnInputPreparation::Ready(input));
    }
    let plan = match serde_json::from_value::<SandboxProcessPlan>(input) {
        Ok(plan) => plan,
        Err(_) => {
            return Ok(SpawnInputPreparation::ModelInputRejected(
                RuntimeCapabilityFailure::new(
                    capability_id.clone(),
                    RuntimeFailureKind::InvalidInput,
                    Some(
                        "process sandbox capability input must be a SandboxProcessPlan".to_string(),
                    ),
                ),
            ));
        }
    };
    let plan = match ValidatedSandboxProcessPlan::new(plan) {
        Ok(plan) => plan,
        Err(_) => {
            return Ok(SpawnInputPreparation::ModelInputRejected(
                RuntimeCapabilityFailure::new(
                    capability_id.clone(),
                    RuntimeFailureKind::InvalidInput,
                    Some(
                        "process sandbox capability input failed SandboxProcessPlan validation"
                            .to_string(),
                    ),
                ),
            ));
        }
    };
    // Serializing the *validated host struct* back to JSON is a host-side
    // operation, not model input. A failure here is a genuine internal fault,
    // so it stays a terminal error rather than a model-visible tool error.
    let value = serde_json::to_value(plan.into_plan()).map_err(|_| {
        HostRuntimeError::invalid_request("validated process sandbox plan could not be serialized")
    })?;
    Ok(SpawnInputPreparation::Ready(value))
}

fn failure_from(
    error: CapabilityInvocationError,
    capability_id: CapabilityId,
) -> RuntimeCapabilityFailure {
    let kind = failure_kind_from(&error);
    let message = sanitized_failure_message(&error);
    let detail = match error {
        CapabilityInvocationError::Dispatch { detail, .. } => detail,
        _ => None,
    };
    let mut failure = RuntimeCapabilityFailure::new(capability_id, kind, message);
    if let Some(detail) = detail {
        failure = failure.with_detail(detail);
    }
    failure
}

/// Returns a stable, redacted summary message for a capability invocation
/// failure.
///
/// Variants that wrap inner errors (`Lease`, `RunState`, `Process`,
/// `InvocationFingerprint`) or that surface free-form storage/runtime
/// strings are mapped to fixed, infrastructure-opaque labels. Variants whose
/// `Display` impl is itself stable (capability id + enum discriminator) flow
/// through unchanged.
fn sanitized_failure_message(error: &CapabilityInvocationError) -> Option<String> {
    use CapabilityInvocationError::*;
    match error {
        UnknownCapability { .. }
        | AuthorizationDenied { .. }
        | UnsupportedObligations { .. }
        | ObligationFailed { .. }
        | AuthorizationRequiresAuth { .. }
        | AuthorizationRequiresApproval { .. }
        | ApprovalRequestMismatch { .. }
        | ApprovalFingerprintMismatch { .. }
        | ApprovalNotApproved { .. }
        | ApprovalLeaseMissing { .. }
        | ApprovalStoreMissing { .. }
        | ResumeStoreMissing { .. }
        | ProcessManagerMissing { .. }
        | ResumeNotBlocked { .. }
        | ResumeContextMismatch { .. } => Some(error.to_string()),
        Dispatch {
            safe_summary, kind, ..
        } => Some(dispatch_failure_message(safe_summary.as_deref(), *kind)),
        InvocationFingerprint { .. } => Some("invocation fingerprint failed".to_string()),
        Lease(_) => Some("capability lease store unavailable".to_string()),
        RunState(_) => Some("run-state store unavailable".to_string()),
        Process(_) => Some("process manager unavailable".to_string()),
    }
}

fn dispatch_failure_message(
    safe_summary: Option<&str>,
    kind: ironclaw_host_api::DispatchFailureKind,
) -> String {
    // Prefer a host-authored safe summary; otherwise fall back to a plain
    // human sentence for the failure category rather than the stable category
    // token (e.g. "the tool input could not be encoded" instead of
    // "dispatch failed: InputEncode").
    safe_summary
        .and_then(|summary| LoopSafeSummary::new(summary).ok())
        .map(|summary| summary.to_string())
        .unwrap_or_else(|| kind.human_summary().to_string())
}

pub(crate) fn failure_kind_from(error: &CapabilityInvocationError) -> RuntimeFailureKind {
    match error {
        CapabilityInvocationError::UnknownCapability { .. } => RuntimeFailureKind::MissingRuntime,
        CapabilityInvocationError::AuthorizationRequiresAuth { .. } => {
            RuntimeFailureKind::Authorization
        }
        CapabilityInvocationError::AuthorizationDenied { .. }
        | CapabilityInvocationError::UnsupportedObligations { .. }
        | CapabilityInvocationError::AuthorizationRequiresApproval { .. }
        | CapabilityInvocationError::ApprovalRequestMismatch { .. }
        | CapabilityInvocationError::ApprovalFingerprintMismatch { .. }
        | CapabilityInvocationError::ApprovalNotApproved { .. }
        | CapabilityInvocationError::ApprovalLeaseMissing { .. }
        | CapabilityInvocationError::ResumeNotBlocked { .. }
        | CapabilityInvocationError::ResumeContextMismatch { .. } => {
            RuntimeFailureKind::Authorization
        }
        CapabilityInvocationError::ObligationFailed { kind, .. } => match kind {
            ironclaw_capabilities::CapabilityObligationFailureKind::Audit => {
                RuntimeFailureKind::Backend
            }
            ironclaw_capabilities::CapabilityObligationFailureKind::Mount => {
                RuntimeFailureKind::Authorization
            }
            ironclaw_capabilities::CapabilityObligationFailureKind::Network => {
                RuntimeFailureKind::Network
            }
            ironclaw_capabilities::CapabilityObligationFailureKind::Output => {
                RuntimeFailureKind::OutputTooLarge
            }
            ironclaw_capabilities::CapabilityObligationFailureKind::Resource => {
                RuntimeFailureKind::Resource
            }
            ironclaw_capabilities::CapabilityObligationFailureKind::Secret => {
                RuntimeFailureKind::Authorization
            }
        },
        CapabilityInvocationError::InvocationFingerprint { .. } => RuntimeFailureKind::InvalidInput,
        CapabilityInvocationError::ApprovalStoreMissing { .. }
        | CapabilityInvocationError::ResumeStoreMissing { .. }
        | CapabilityInvocationError::ProcessManagerMissing { .. } => RuntimeFailureKind::Backend,
        CapabilityInvocationError::Lease(_)
        | CapabilityInvocationError::RunState(_)
        | CapabilityInvocationError::Process(_) => RuntimeFailureKind::Backend,
        CapabilityInvocationError::Dispatch { kind, .. } => RuntimeFailureKind::from(*kind),
    }
}

impl From<DispatchFailureKind> for RuntimeFailureKind {
    fn from(kind: DispatchFailureKind) -> Self {
        match kind {
            DispatchFailureKind::UnknownCapability | DispatchFailureKind::UnknownProvider => {
                RuntimeFailureKind::InvalidOutput
            }
            DispatchFailureKind::MissingRuntimeBackend
            | DispatchFailureKind::UnsupportedRuntime => RuntimeFailureKind::MissingRuntime,
            DispatchFailureKind::AuthRequired => RuntimeFailureKind::Authorization,
            DispatchFailureKind::RuntimeMismatch => RuntimeFailureKind::Backend,
            DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::ExtensionRuntimeMismatch) => {
                RuntimeFailureKind::MissingRuntime
            }
            DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::Memory)
            | DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::Resource) => {
                RuntimeFailureKind::Resource
            }
            DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::NetworkDenied) => {
                RuntimeFailureKind::Network
            }
            DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::PolicyDenied) => {
                RuntimeFailureKind::PolicyDenied
            }
            DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::OutputTooLarge) => {
                RuntimeFailureKind::OutputTooLarge
            }
            DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::FilesystemDenied) => {
                RuntimeFailureKind::Authorization
            }
            DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::SecretDenied) => {
                RuntimeFailureKind::Authorization
            }
            DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::ExitFailure) => {
                RuntimeFailureKind::Process
            }
            DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::InputEncode) => {
                RuntimeFailureKind::InvalidInput
            }
            DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::OutputDecode)
            | DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::InvalidResult) => {
                RuntimeFailureKind::InvalidOutput
            }
            DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::OperationFailed) => {
                RuntimeFailureKind::OperationFailed
            }
            // A method or capability the model named that does not exist is a
            // model-fixable request error, not an infra fault: classify it as
            // InvalidInput so it surfaces as an immediate model-visible tool
            // error instead of burning the retry budget on a call that can
            // never resolve by retrying.
            DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::MethodMissing)
            | DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::UndeclaredCapability) => {
                RuntimeFailureKind::InvalidInput
            }
            DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::Backend)
            | DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::Client)
            | DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::Executor)
            | DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::Guest)
            | DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::Manifest)
            | DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::UnsupportedRunner) => {
                RuntimeFailureKind::Backend
            }
            // The fail-safe "uncategorized" redaction bucket collapses to a
            // concrete internal failure rather than propagating a dedicated
            // `Unknown` category downstream. `Internal` is retryable and
            // surfaces to the model/user, so an unclassified dispatch error is
            // no longer an opaque run-ending dead-end. See
            // `docs/plans/2026-06-28-reborn-error-recoverability-audit.md`.
            DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::Unknown) => Self::Internal,
        }
    }
}

#[cfg(test)]
mod tests {
    //! Pinning tests for the host-runtime failure-kind and sanitized-message
    //! mappings.
    //!
    //! The dispatch failure kinds come from typed
    //! [`ironclaw_host_api::DispatchFailureKind`] values. Their display
    //! strings remain part of the public observability contract, but runtime
    //! failure mapping stays type-directed instead of reparsing strings.

    use super::*;
    use ironclaw_capabilities::CapabilityInvocationError;
    use ironclaw_extensions::{
        ExtensionManifest, ExtensionPackage, ExtensionRegistry, ManifestSource,
    };
    use ironclaw_filesystem::{FilesystemError, FilesystemOperation};
    use ironclaw_host_api::{
        CapabilityId, DispatchFailureKind, ExtensionId, HostPortCatalog, PackageSource,
        RuntimeCredentialAccountProviderId, RuntimeCredentialAuthRequirement,
        RuntimeDispatchErrorKind, SecretHandle, VirtualPath, sha256_digest_token,
    };

    fn cap() -> CapabilityId {
        CapabilityId::new("test.cap").unwrap()
    }

    /// Regression for the wiring in `DefaultHostRuntime::visible_capabilities`
    /// (this file, ~:1050): a `with_hosted_mcp_overlay` attachment must
    /// actually reach `CapabilityCatalog`, not just compile. Drives the real
    /// production entry point end to end — `DefaultHostRuntime` +
    /// `HostRuntime::visible_capabilities` — with a spy overlay, so a
    /// regression that drops the `self.hosted_mcp_overlay.as_deref()`
    /// pass-through fails loudly here instead of silently no-opping.
    mod hosted_mcp_overlay_wiring {
        use super::*;
        use crate::{CapabilitySurfacePolicy, HireScope, HostedMcpOverlayError, SurfaceKind};
        use ironclaw_host_api::{
            Action, AgentId, ApprovalRequest, CapabilityDescriptor, CapabilityDispatchRequest,
            CapabilityDispatchResult, DispatchError, EffectKind, ExecutionContext,
            GrantConstraints, MountView, NetworkPolicy, Obligations, ProjectId, ReservationStatus,
            ResourceReceipt, ResourceReservationId, ResourceUsage, TenantId, UserId,
        };
        use ironclaw_run_state::{InMemoryApprovalRequestStore, InMemoryRunStateStore};
        use std::sync::Mutex as StdMutex;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct UnusedDispatcher;

        #[async_trait]
        impl CapabilityDispatcher for UnusedDispatcher {
            async fn dispatch_json(
                &self,
                _request: CapabilityDispatchRequest,
            ) -> Result<CapabilityDispatchResult, DispatchError> {
                unreachable!("visible_capabilities must never dispatch a capability")
            }
        }

        struct AllowAllAuthorizer;

        #[async_trait]
        impl TrustAwareCapabilityDispatchAuthorizer for AllowAllAuthorizer {
            async fn authorize_dispatch_with_trust(
                &self,
                _context: &ExecutionContext,
                _descriptor: &CapabilityDescriptor,
                _estimate: &ResourceEstimate,
                _trust_decision: &ironclaw_trust::TrustDecision,
            ) -> Decision {
                Decision::Allow {
                    obligations: Obligations::default(),
                }
            }
        }

        struct SpyOverlay {
            calls: AtomicUsize,
        }

        #[async_trait]
        impl HostedMcpSurfaceOverlay for SpyOverlay {
            async fn overlay_capabilities(
                &self,
                _hire: &HireScope,
                _package: &ExtensionPackage,
            ) -> Result<Vec<CapabilityDescriptor>, HostedMcpOverlayError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(Vec::new())
            }
        }

        fn hosted_mcp_registry() -> ExtensionRegistry {
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
            let manifest = ExtensionManifest::parse(
                MANIFEST,
                ManifestSource::HostBundled,
                &HostPortCatalog::default(),
            )
            .unwrap();
            let package = ExtensionPackage::from_manifest(
                manifest,
                VirtualPath::new("/system/extensions/notion").unwrap(),
            )
            .unwrap();
            let mut registry = ExtensionRegistry::new();
            registry.insert(package).unwrap();
            registry
        }

        fn test_runtime_policy() -> EffectiveRuntimePolicy {
            EffectiveRuntimePolicy {
                deployment: ironclaw_host_api::runtime_policy::DeploymentMode::LocalSingleUser,
                requested_profile: ironclaw_host_api::runtime_policy::RuntimeProfile::SecureDefault,
                resolved_profile: ironclaw_host_api::runtime_policy::RuntimeProfile::SecureDefault,
                filesystem_backend:
                    ironclaw_host_api::runtime_policy::FilesystemBackendKind::ScopedVirtual,
                process_backend: ironclaw_host_api::runtime_policy::ProcessBackendKind::None,
                network_mode: ironclaw_host_api::runtime_policy::NetworkMode::Brokered,
                secret_mode: ironclaw_host_api::runtime_policy::SecretMode::BrokeredHandles,
                approval_policy: ironclaw_host_api::runtime_policy::ApprovalPolicy::AskAlways,
                audit_mode: ironclaw_host_api::runtime_policy::AuditMode::LocalMinimal,
            }
        }

        /// Builds a request scoped to `agent`, independently from any other
        /// call — no shared `hire()`-style object between two calls of this
        /// function, so a multi-tenant test built from two independent
        /// invocations proves isolation along the real
        /// `ExecutionContext`/`ResourceScope` construction path, not just
        /// two hand-built structs that happen to differ in one field.
        fn agent_scoped_request(agent: &str) -> VisibleCapabilityRequest {
            let user_id = UserId::new("buyer-1").unwrap();
            let mut context = ExecutionContext::local_default(
                user_id,
                ExtensionId::new("notion").unwrap(),
                RuntimeKind::Mcp,
                ironclaw_host_api::TrustClass::UserTrusted,
                Default::default(),
                Default::default(),
            )
            .unwrap();
            let tenant_id = TenantId::new("acme").unwrap();
            let agent_id = Some(AgentId::new(agent).unwrap());
            let project_id = Some(ProjectId::new("proj-1").unwrap());
            context.tenant_id = tenant_id.clone();
            context.agent_id = agent_id.clone();
            context.project_id = project_id.clone();
            context.resource_scope.tenant_id = tenant_id;
            context.resource_scope.agent_id = agent_id;
            context.resource_scope.project_id = project_id;
            context.validate().unwrap();

            let mut provider_trust = std::collections::BTreeMap::new();
            provider_trust.insert(
                ExtensionId::new("notion").unwrap(),
                ironclaw_trust::TrustDecision {
                    effective_trust: ironclaw_trust::EffectiveTrustClass::user_trusted(),
                    authority_ceiling: ironclaw_trust::AuthorityCeiling {
                        allowed_effects: vec![EffectKind::DispatchCapability, EffectKind::Network],
                        max_resource_ceiling: None,
                    },
                    provenance: ironclaw_trust::TrustProvenance::AdminConfig,
                    evaluated_at: chrono::Utc::now(),
                },
            );

            VisibleCapabilityRequest::new(context, SurfaceKind::new("test").unwrap())
                .with_policy(CapabilitySurfacePolicy::allow_all())
                .with_provider_trust(provider_trust)
        }

        #[tokio::test]
        async fn attached_overlay_is_consulted_through_default_host_runtime() {
            let registry = Arc::new(hosted_mcp_registry());
            let dispatcher: Arc<dyn CapabilityDispatcher> = Arc::new(UnusedDispatcher);
            let authorizer: Arc<dyn TrustAwareCapabilityDispatchAuthorizer> =
                Arc::new(AllowAllAuthorizer);
            let overlay = Arc::new(SpyOverlay {
                calls: AtomicUsize::new(0),
            });
            let runtime = DefaultHostRuntime::new(
                registry,
                dispatcher,
                authorizer,
                CapabilitySurfaceVersion::new("surface-v1").unwrap(),
                test_runtime_policy(),
            )
            .with_hosted_mcp_overlay(overlay.clone());

            runtime
                .visible_capabilities(agent_scoped_request("agent-1"))
                .await
                .expect("visible_capabilities succeeds");

            assert_eq!(
                overlay.calls.load(Ordering::SeqCst),
                1,
                "an attached overlay must be consulted for an agent-scoped turn \
                 — if this is 0, the DefaultHostRuntime -> CapabilityCatalog \
                 wiring dropped the overlay"
            );
        }

        /// C (multi-tenant isolation) regression, required by review item 4:
        /// two turns differing ONLY in `agent_id`, each built from an
        /// independently-constructed `ExecutionContext` (not a shared
        /// `hire()`-style helper), driven through the real
        /// `DefaultHostRuntime::visible_capabilities`. This is the layer
        /// where a regression that accidentally coalesced scope fields
        /// upstream of `HireScope::from_scope` would first be visible — the
        /// composition-tier cache test starts from a hand-built
        /// `ResourceScope`, not this production construction path.
        #[tokio::test]
        async fn multi_tenant_turns_see_only_their_own_overlay_capabilities() {
            struct PerAgentOverlay;

            #[async_trait]
            impl HostedMcpSurfaceOverlay for PerAgentOverlay {
                async fn overlay_capabilities(
                    &self,
                    hire: &HireScope,
                    _package: &ExtensionPackage,
                ) -> Result<Vec<CapabilityDescriptor>, HostedMcpOverlayError> {
                    let agent = hire.agent_id().as_str();
                    Ok(vec![CapabilityDescriptor {
                        id: CapabilityId::new(format!("notion.tool-for-{agent}")).unwrap(),
                        provider: ExtensionId::new("notion").unwrap(),
                        runtime: RuntimeKind::Mcp,
                        trust_ceiling: ironclaw_host_api::TrustClass::UserTrusted,
                        description: format!("tool discovered for {agent}"),
                        parameters_schema: serde_json::json!({"type": "object"}),
                        effects: vec![EffectKind::DispatchCapability, EffectKind::Network],
                        default_permission: ironclaw_host_api::PermissionMode::Ask,
                        runtime_credentials: Vec::new(),
                        resource_profile: None,
                    }])
                }
            }

            let registry = Arc::new(hosted_mcp_registry());
            let dispatcher: Arc<dyn CapabilityDispatcher> = Arc::new(UnusedDispatcher);
            let authorizer: Arc<dyn TrustAwareCapabilityDispatchAuthorizer> =
                Arc::new(AllowAllAuthorizer);
            let runtime = DefaultHostRuntime::new(
                registry,
                dispatcher,
                authorizer,
                CapabilitySurfaceVersion::new("surface-v1").unwrap(),
                test_runtime_policy(),
            )
            .with_hosted_mcp_overlay(Arc::new(PerAgentOverlay));

            let surface_a = runtime
                .visible_capabilities(agent_scoped_request("agent-a"))
                .await
                .expect("agent-a surface builds");
            let surface_b = runtime
                .visible_capabilities(agent_scoped_request("agent-b"))
                .await
                .expect("agent-b surface builds");

            let has_id = |surface: &VisibleCapabilitySurface, id: &str| {
                surface
                    .capabilities
                    .iter()
                    .any(|capability| capability.descriptor.id.as_str() == id)
            };
            assert!(
                has_id(&surface_a, "notion.tool-for-agent-a"),
                "agent-a must see its own discovered tool"
            );
            assert!(
                !has_id(&surface_a, "notion.tool-for-agent-b"),
                "agent-a must NOT see agent-b's discovered tool"
            );
            assert!(
                has_id(&surface_b, "notion.tool-for-agent-b"),
                "agent-b must see its own discovered tool"
            );
            assert!(
                !has_id(&surface_b, "notion.tool-for-agent-a"),
                "agent-b must NOT see agent-a's discovered tool"
            );
            assert!(
                has_id(&surface_a, "notion.notion-fetch")
                    && has_id(&surface_b, "notion.notion-fetch"),
                "the static floor must still be present for both agents"
            );
        }

        fn discovered_descriptor(id: &str) -> CapabilityDescriptor {
            CapabilityDescriptor {
                id: CapabilityId::new(id).unwrap(),
                provider: ExtensionId::new("notion").unwrap(),
                runtime: RuntimeKind::Mcp,
                trust_ceiling: ironclaw_host_api::TrustClass::UserTrusted,
                description: "discovered tool".to_string(),
                parameters_schema: serde_json::json!({"type": "object"}),
                effects: vec![EffectKind::DispatchCapability, EffectKind::Network],
                default_permission: ironclaw_host_api::PermissionMode::Ask,
                runtime_credentials: Vec::new(),
                resource_profile: None,
            }
        }

        fn runtime_with_overlay(overlay: Arc<dyn HostedMcpSurfaceOverlay>) -> DefaultHostRuntime {
            let registry = Arc::new(hosted_mcp_registry());
            let dispatcher: Arc<dyn CapabilityDispatcher> = Arc::new(UnusedDispatcher);
            let authorizer: Arc<dyn TrustAwareCapabilityDispatchAuthorizer> =
                Arc::new(AllowAllAuthorizer);
            DefaultHostRuntime::new(
                registry,
                dispatcher,
                authorizer,
                CapabilitySurfaceVersion::new("surface-v1").unwrap(),
                test_runtime_policy(),
            )
            .with_hosted_mcp_overlay(overlay)
        }

        fn agent_scope(agent: &str) -> ResourceScope {
            agent_scoped_request(agent).context.resource_scope
        }

        /// P1 unit coverage for `resolve_invocation_registry`: a floor
        /// capability resolves via the plain snapshot at zero extra cost —
        /// same `Arc` pointer, not a clone.
        #[tokio::test]
        async fn resolve_invocation_registry_returns_plain_snapshot_for_a_floor_hit() {
            let overlay = Arc::new(SpyOverlay {
                calls: AtomicUsize::new(0),
            });
            let runtime = runtime_with_overlay(overlay.clone());

            let resolved = runtime
                .resolve_invocation_registry(
                    &agent_scope("agent-1"),
                    &CapabilityId::new("notion.notion-fetch").unwrap(),
                )
                .await;

            assert!(
                Arc::ptr_eq(&resolved, &runtime.registry.snapshot()),
                "a floor hit must return the SAME registry Arc — zero clone cost"
            );
            assert_eq!(
                overlay.calls.load(Ordering::SeqCst),
                0,
                "a floor hit must never consult the overlay"
            );
        }

        /// P1 unit coverage: a discovered capability id (registry miss) is
        /// resolved into a per-request merged registry, without ever
        /// mutating the shared boot registry.
        #[tokio::test]
        async fn resolve_invocation_registry_merges_a_discovered_capability_on_miss() {
            struct OneToolOverlay;

            #[async_trait]
            impl HostedMcpSurfaceOverlay for OneToolOverlay {
                async fn overlay_capabilities(
                    &self,
                    _hire: &HireScope,
                    _package: &ExtensionPackage,
                ) -> Result<Vec<CapabilityDescriptor>, HostedMcpOverlayError> {
                    Ok(vec![discovered_descriptor("notion.live-search")])
                }
            }

            let runtime = runtime_with_overlay(Arc::new(OneToolOverlay));
            let capability_id = CapabilityId::new("notion.live-search").unwrap();

            let resolved = runtime
                .resolve_invocation_registry(&agent_scope("agent-1"), &capability_id)
                .await;

            assert!(
                resolved.get_capability(&capability_id).is_some(),
                "the discovered capability must be resolvable in the merged registry"
            );
            assert!(
                runtime
                    .registry
                    .snapshot()
                    .get_capability(&capability_id)
                    .is_none(),
                "the shared boot registry must never be mutated by resolution"
            );
        }

        /// Fail-safe: no `agent_id` on scope (`HireScope::from_scope` is
        /// `None`) must fall through to the plain snapshot without
        /// consulting the overlay — the existing `UnknownCapability` path.
        #[tokio::test]
        async fn resolve_invocation_registry_falls_back_without_an_agent_scope() {
            let overlay = Arc::new(SpyOverlay {
                calls: AtomicUsize::new(0),
            });
            let runtime = runtime_with_overlay(overlay.clone());
            let mut scope = agent_scope("agent-1");
            scope.agent_id = None;

            let resolved = runtime
                .resolve_invocation_registry(
                    &scope,
                    &CapabilityId::new("notion.live-search").unwrap(),
                )
                .await;

            assert!(
                resolved
                    .get_capability(&CapabilityId::new("notion.live-search").unwrap())
                    .is_none()
            );
            assert_eq!(
                overlay.calls.load(Ordering::SeqCst),
                0,
                "no agent_id must never consult the overlay (leak gate)"
            );
        }

        /// Fail-safe: a genuinely-unknown capability id (not in the floor,
        /// not returned by discovery) falls back to the plain snapshot —
        /// still `UnknownCapability`, never a hang or a panic.
        #[tokio::test]
        async fn resolve_invocation_registry_falls_back_when_nothing_matches() {
            let runtime = runtime_with_overlay(Arc::new(SpyOverlay {
                calls: AtomicUsize::new(0),
            }));

            let resolved = runtime
                .resolve_invocation_registry(
                    &agent_scope("agent-1"),
                    &CapabilityId::new("notion.hallucinated-tool").unwrap(),
                )
                .await;

            assert!(
                resolved
                    .get_capability(&CapabilityId::new("notion.hallucinated-tool").unwrap())
                    .is_none()
            );
        }

        /// Multi-tenant isolation AT INVOKE (not just at surface build):
        /// worker A's `resolve_invocation_registry` never resolves worker
        /// B's discovered tool, and vice versa, each built from an
        /// independently-constructed scope — matching
        /// `multi_tenant_turns_see_only_their_own_overlay_capabilities`'s
        /// discipline but for the invoke-time resolution path this slice
        /// adds. Isolation here is structural: `PerAgentOverlay` keys its
        /// response purely off `hire.agent_id()`, so a leak would mean
        /// `HireScope`/`resource_scope.agent_id` itself was coalesced
        /// upstream — exactly the regression this test would catch first.
        #[tokio::test]
        async fn resolve_invocation_registry_isolates_discovered_capabilities_across_agents() {
            struct PerAgentOverlay;

            #[async_trait]
            impl HostedMcpSurfaceOverlay for PerAgentOverlay {
                async fn overlay_capabilities(
                    &self,
                    hire: &HireScope,
                    _package: &ExtensionPackage,
                ) -> Result<Vec<CapabilityDescriptor>, HostedMcpOverlayError> {
                    let agent = hire.agent_id().as_str();
                    Ok(vec![discovered_descriptor(&format!(
                        "notion.tool-for-{agent}"
                    ))])
                }
            }

            let runtime = runtime_with_overlay(Arc::new(PerAgentOverlay));

            let resolved_a = runtime
                .resolve_invocation_registry(
                    &agent_scope("agent-a"),
                    &CapabilityId::new("notion.tool-for-agent-a").unwrap(),
                )
                .await;
            let resolved_b = runtime
                .resolve_invocation_registry(
                    &agent_scope("agent-b"),
                    &CapabilityId::new("notion.tool-for-agent-b").unwrap(),
                )
                .await;

            assert!(
                resolved_a
                    .get_capability(&CapabilityId::new("notion.tool-for-agent-a").unwrap())
                    .is_some(),
                "agent-a must resolve its own discovered tool"
            );
            assert!(
                resolved_a
                    .get_capability(&CapabilityId::new("notion.tool-for-agent-b").unwrap())
                    .is_none(),
                "agent-a's registry must NOT resolve agent-b's discovered tool id, \
                 even though agent-a's own resolution ran against the SAME base \
                 registry/overlay pair"
            );
            assert!(
                resolved_b
                    .get_capability(&CapabilityId::new("notion.tool-for-agent-b").unwrap())
                    .is_some(),
                "agent-b must resolve its own discovered tool"
            );
            assert!(
                resolved_b
                    .get_capability(&CapabilityId::new("notion.tool-for-agent-a").unwrap())
                    .is_none(),
                "agent-b's registry must NOT resolve agent-a's discovered tool id"
            );
            // Cross-check: worker A attempting to invoke worker B's id directly
            // (not just omitted from A's own successful resolution) also
            // fails to resolve — this is the actual invoke-time attack shape.
            let cross_attempt = runtime
                .resolve_invocation_registry(
                    &agent_scope("agent-a"),
                    &CapabilityId::new("notion.tool-for-agent-b").unwrap(),
                )
                .await;
            assert!(
                cross_attempt
                    .get_capability(&CapabilityId::new("notion.tool-for-agent-b").unwrap())
                    .is_none(),
                "worker A must not be able to resolve worker B's discovered \
                 capability id even by naming it directly"
            );
        }

        /// M1 negative: a discovered hosted-MCP capability is `runtime =
        /// Mcp`, dispatch-only, and must never become reachable by
        /// `spawn_capability` — that lane deliberately stays on the plain
        /// registry snapshot (never calls `resolve_invocation_registry`),
        /// so a discovered id is `UnknownCapability` there regardless of
        /// what invoke/resume can resolve.
        #[tokio::test]
        async fn discovered_hosted_mcp_capability_never_reaches_spawn_lane() {
            struct OneToolOverlay;

            #[async_trait]
            impl HostedMcpSurfaceOverlay for OneToolOverlay {
                async fn overlay_capabilities(
                    &self,
                    _hire: &HireScope,
                    _package: &ExtensionPackage,
                ) -> Result<Vec<CapabilityDescriptor>, HostedMcpOverlayError> {
                    Ok(vec![discovered_descriptor("notion.live-search")])
                }
            }

            let runtime = runtime_with_overlay(Arc::new(OneToolOverlay));
            let capability_id = CapabilityId::new("notion.live-search").unwrap();

            // Sanity: invoke-side resolution DOES find it (proves the overlay
            // wiring itself is live, so the spawn-lane negative below is
            // meaningful rather than vacuous).
            let invoke_side = runtime
                .resolve_invocation_registry(&agent_scope("agent-1"), &capability_id)
                .await;
            assert!(invoke_side.get_capability(&capability_id).is_some());

            // Spawn's own plain snapshot never sees it.
            assert!(
                runtime
                    .registry
                    .snapshot()
                    .get_capability(&capability_id)
                    .is_none(),
                "the plain registry snapshot spawn_capability/resume_spawn_capability \
                 use must never resolve a discovered hosted-MCP capability"
            );
        }

        /// Records every `CapabilityDispatchRequest` it receives and returns a
        /// canned success — the "did the dispatcher actually see the merged
        /// descriptor" probe for the C1 regression below.
        struct SpyDispatcher {
            recorded: StdMutex<Vec<CapabilityDispatchRequest>>,
        }

        impl SpyDispatcher {
            fn new() -> Self {
                Self {
                    recorded: StdMutex::new(Vec::new()),
                }
            }

            fn last_request(&self) -> CapabilityDispatchRequest {
                self.recorded
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .last()
                    .cloned()
                    .expect("dispatch_json must have been called")
            }
        }

        #[async_trait]
        impl CapabilityDispatcher for SpyDispatcher {
            async fn dispatch_json(
                &self,
                request: CapabilityDispatchRequest,
            ) -> Result<CapabilityDispatchResult, DispatchError> {
                let capability_id = request.capability_id.clone();
                let scope = request.scope.clone();
                self.recorded
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(request);
                Ok(CapabilityDispatchResult {
                    capability_id,
                    provider: ExtensionId::new("notion").unwrap(),
                    runtime: RuntimeKind::Mcp,
                    output: serde_json::json!({"result": "ok"}),
                    display_preview: None,
                    usage: ResourceUsage::default(),
                    receipt: ResourceReceipt {
                        id: ResourceReservationId::new(),
                        scope,
                        status: ReservationStatus::Reconciled,
                        estimate: ResourceEstimate::default(),
                        actual: None,
                    },
                })
            }
        }

        /// Gates the FIRST dispatch attempt on an empty grant set (the shape
        /// invoke sees, before approval) and delegates to the real
        /// `GrantAuthorizer` once a grant is present (the shape resume sees,
        /// after `CapabilityHost::resume_json` injects the approved lease's
        /// grant into the authorized context) — mirrors
        /// `reborn_e2e_gate.rs`'s `ApprovalThenGrantAuthorizer` for the
        /// discovered-capability path.
        struct GateThenGrantAuthorizer;

        #[async_trait]
        impl TrustAwareCapabilityDispatchAuthorizer for GateThenGrantAuthorizer {
            async fn authorize_dispatch_with_trust(
                &self,
                context: &ExecutionContext,
                descriptor: &CapabilityDescriptor,
                estimate: &ResourceEstimate,
                trust_decision: &ironclaw_trust::TrustDecision,
            ) -> Decision {
                if context.grants.grants.is_empty() {
                    Decision::RequireApproval {
                        request: ApprovalRequest {
                            id: ApprovalRequestId::new(),
                            correlation_id: context.correlation_id,
                            requested_by: Principal::Extension(context.extension_id.clone()),
                            action: Box::new(Action::Dispatch {
                                capability: descriptor.id.clone(),
                                estimated_resources: estimate.clone(),
                            }),
                            invocation_fingerprint: None,
                            reason: "approval required".to_string(),
                            reusable_scope: None,
                        },
                    }
                } else {
                    ironclaw_authorization::GrantAuthorizer::new()
                        .authorize_dispatch_with_trust(
                            context,
                            descriptor,
                            estimate,
                            trust_decision,
                        )
                        .await
                }
            }
        }

        fn discovered_capability_trust_policy() -> ironclaw_trust::HostTrustPolicy {
            ironclaw_trust::HostTrustPolicy::new(vec![Box::new(
                ironclaw_trust::AdminConfig::with_entries(vec![
                    ironclaw_trust::AdminEntry::for_local_manifest(
                        ironclaw_host_api::PackageId::new("notion").unwrap(),
                        "/system/extensions/notion/manifest.toml".to_string(),
                        None,
                        ironclaw_trust::HostTrustAssignment::user_trusted(),
                        vec![EffectKind::DispatchCapability],
                        None,
                    ),
                ]),
            )])
            .unwrap()
        }

        fn discovered_capability_trust_decision() -> ironclaw_trust::TrustDecision {
            ironclaw_trust::TrustDecision {
                effective_trust: ironclaw_trust::EffectiveTrustClass::user_trusted(),
                authority_ceiling: ironclaw_trust::AuthorityCeiling {
                    allowed_effects: vec![EffectKind::DispatchCapability],
                    max_resource_ceiling: None,
                },
                provenance: ironclaw_trust::TrustProvenance::Default,
                evaluated_at: chrono::Utc::now(),
            }
        }

        /// C1 wired regression (review item 1): drives the REAL
        /// invoke -> approve -> resume sequence for a DISCOVERED hosted-MCP
        /// capability through `DefaultHostRuntime` end to end — the exact bug
        /// this slice fixes (`UnknownCapability` at both preflights) is
        /// provable only by driving the caller, not by reading
        /// `resolve_invocation_registry` in isolation. A dispatch-only
        /// `SpyDispatcher` stands in for the real MCP runtime adapter (which
        /// needs the integration-tier harness, tracked separately) but still
        /// proves the load-bearing claim: the dispatcher receives
        /// `descriptor: Some(..)` — i.e. the MERGED per-request descriptor
        /// threaded all the way through, not a silent registry re-resolve
        /// that would have failed `UnknownCapability` on its own.
        ///
        /// Deliberately does NOT reuse the `runtime_with_overlay` helper
        /// above (which wires `AllowAllAuthorizer`): this test's whole point
        /// is proving invoke raises a real `RequireApproval` gate — an
        /// always-`Allow` authorizer would never produce one, so the C1
        /// regression (resume re-resolving the plain registry and failing
        /// `UnknownCapability`) couldn't be exercised. `GateThenGrantAuthorizer`
        /// below reproduces the two authorization shapes invoke/resume
        /// actually see (empty grants -> gate; grant present -> real
        /// `GrantAuthorizer`).
        #[tokio::test]
        async fn discovered_capability_invoke_approve_resume_completes_through_merged_registry() {
            struct OneToolOverlay;

            #[async_trait]
            impl HostedMcpSurfaceOverlay for OneToolOverlay {
                async fn overlay_capabilities(
                    &self,
                    _hire: &HireScope,
                    _package: &ExtensionPackage,
                ) -> Result<Vec<CapabilityDescriptor>, HostedMcpOverlayError> {
                    // DispatchCapability-only (no Network/secrets): keeps this
                    // fixture obligation-free (no `ApplyNetworkPolicy` /
                    // `InjectSecretOnce`), which needs no
                    // `CapabilityObligationHandler` wiring — this test is
                    // about the invoke/resume descriptor-resolution wiring,
                    // not obligation handling (covered elsewhere).
                    Ok(vec![CapabilityDescriptor {
                        id: CapabilityId::new("notion.live-search").unwrap(),
                        provider: ExtensionId::new("notion").unwrap(),
                        runtime: RuntimeKind::Mcp,
                        trust_ceiling: ironclaw_host_api::TrustClass::UserTrusted,
                        description: "discovered tool".to_string(),
                        parameters_schema: serde_json::json!({"type": "object"}),
                        effects: vec![EffectKind::DispatchCapability],
                        default_permission: ironclaw_host_api::PermissionMode::Ask,
                        runtime_credentials: Vec::new(),
                        resource_profile: None,
                    }])
                }
            }

            let registry = Arc::new(hosted_mcp_registry());
            let dispatcher = Arc::new(SpyDispatcher::new());
            let run_state = Arc::new(InMemoryRunStateStore::new());
            let approval_requests = Arc::new(InMemoryApprovalRequestStore::new());
            let capability_leases =
                Arc::new(ironclaw_authorization::InMemoryCapabilityLeaseStore::new());
            let runtime = DefaultHostRuntime::new(
                registry,
                dispatcher.clone() as Arc<dyn CapabilityDispatcher>,
                Arc::new(GateThenGrantAuthorizer)
                    as Arc<dyn TrustAwareCapabilityDispatchAuthorizer>,
                CapabilitySurfaceVersion::new("surface-v1").unwrap(),
                test_runtime_policy(),
            )
            .with_trust_policy(Arc::new(discovered_capability_trust_policy()))
            .with_run_state(run_state)
            .with_approval_requests(
                Arc::clone(&approval_requests) as Arc<dyn ironclaw_run_state::ApprovalRequestStore>
            )
            .with_capability_leases(Arc::clone(&capability_leases) as Arc<dyn CapabilityLeaseStore>)
            .with_hosted_mcp_overlay(Arc::new(OneToolOverlay));

            let capability_id = CapabilityId::new("notion.live-search").unwrap();
            let context = agent_scoped_request("agent-1").context;
            let scope = context.resource_scope.clone();
            let estimate = ResourceEstimate::default();
            let input = serde_json::json!({"query": "reborn invoke-path"});

            let invoked = runtime
                .invoke_capability(RuntimeCapabilityRequest::new(
                    context.clone(),
                    capability_id.clone(),
                    estimate.clone(),
                    input.clone(),
                    discovered_capability_trust_decision(),
                ))
                .await
                .expect("invoke must not error");
            let gate = match invoked {
                RuntimeCapabilityOutcome::ApprovalRequired(gate) => gate,
                other => panic!(
                    "expected an approval gate for a discovered Ask-permission \
                     capability, not {other:?} — a Failed{{UnknownCapability}} here \
                     means the per-request registry merge regressed"
                ),
            };

            let lease = ironclaw_approvals::ApprovalResolver::new(
                approval_requests.as_ref(),
                capability_leases.as_ref(),
            )
            .approve_dispatch(
                &scope,
                gate.approval_request_id,
                ironclaw_approvals::LeaseApproval {
                    issued_by: Principal::HostRuntime,
                    constraints: GrantConstraints {
                        allowed_effects: vec![EffectKind::DispatchCapability],
                        mounts: MountView::default(),
                        network: NetworkPolicy::default(),
                        secrets: Vec::new(),
                        resource_ceiling: None,
                        expires_at: None,
                        max_invocations: Some(1),
                    },
                },
            )
            .await
            .expect("approval must issue a one-shot lease");
            assert_eq!(lease.grant.capability, capability_id);

            let resumed = runtime
                .resume_capability(RuntimeCapabilityResumeRequest::new(
                    context,
                    gate.approval_request_id,
                    capability_id.clone(),
                    estimate,
                    input,
                    discovered_capability_trust_decision(),
                ))
                .await
                .expect("resume must not error");
            match resumed {
                RuntimeCapabilityOutcome::Completed(completed) => {
                    assert_eq!(completed.capability_id, capability_id);
                }
                other => panic!(
                    "expected the approved discovered capability to complete, \
                     not {other:?} — this is the C1 bug this slice fixes: \
                     resume re-resolving the PLAIN registry would fail \
                     UnknownCapability even though invoke correctly gated it"
                ),
            }

            // The load-bearing assertion: the dispatcher received the MERGED
            // descriptor, proving `resolve_invocation_registry` threaded all
            // the way through resume into the `CapabilityDispatchRequest` —
            // not just that SOME success outcome came back.
            let dispatched = dispatcher.last_request();
            assert_eq!(dispatched.capability_id, capability_id);
            let received_descriptor = dispatched
                .descriptor
                .expect("the dispatcher must receive the per-request merged descriptor");
            assert_eq!(received_descriptor.id, capability_id);
            assert_eq!(received_descriptor.runtime, RuntimeKind::Mcp);
        }
    }

    fn dispatch(kind: DispatchFailureKind) -> CapabilityInvocationError {
        CapabilityInvocationError::Dispatch {
            kind,
            safe_summary: None,
            detail: None,
        }
    }

    fn auth_requirement(scopes: &[&str]) -> RuntimeCredentialAuthRequirement {
        RuntimeCredentialAuthRequirement {
            provider: RuntimeCredentialAccountProviderId::new("notion").unwrap(),
            setup: ironclaw_host_api::RuntimeCredentialAccountSetup::OAuth {
                scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
            },
            requester_extension: ExtensionId::new("notion").unwrap(),
            provider_scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
        }
    }

    #[test]
    fn local_manifest_trust_input_includes_manifest_digest() {
        const MANIFEST: &str = r#"
schema_version = "reborn.extension_manifest.v2"
id = "test"
name = "Test"
version = "0.1.0"
description = "test extension"
trust = "third_party"

[runtime]
kind = "script"
runner = "sandboxed_process"
command = "echo"

[[capabilities]]
id = "test.cap"
description = "Test capability"
effects = ["network"]
default_permission = "ask"
visibility = "model"
input_schema_ref = "schemas/test.input.json"
output_schema_ref = "schemas/test.output.json"
"#;
        let manifest = ExtensionManifest::parse(
            MANIFEST,
            ManifestSource::HostBundled,
            &HostPortCatalog::empty(),
        )
        .unwrap();
        let package = ExtensionPackage::from_manifest_toml(
            manifest,
            VirtualPath::new("/system/extensions/test").unwrap(),
            MANIFEST,
        )
        .unwrap();

        let input = trust_policy_input_for_local_manifest(&package).unwrap();

        assert_eq!(
            input.identity.source,
            PackageSource::LocalManifest {
                path: "/system/extensions/test/manifest.toml".to_string()
            }
        );
        let expected_digest = sha256_digest_token(MANIFEST.as_bytes());
        assert_eq!(
            input.identity.digest.as_deref(),
            Some(expected_digest.as_str())
        );
    }

    #[test]
    fn auth_required_outcome_uses_stable_gate_for_identical_requirements() {
        let capability_id = cap();
        let secrets = vec![SecretHandle::new("notion-token").unwrap()];
        let requirements = vec![auth_requirement(&["read", "write"])];

        let first =
            auth_required_outcome(capability_id.clone(), secrets.clone(), requirements.clone());
        let second = auth_required_outcome(capability_id, secrets, requirements);

        let RuntimeCapabilityOutcome::AuthRequired(first_gate) = first else {
            panic!("expected auth gate");
        };
        let RuntimeCapabilityOutcome::AuthRequired(second_gate) = second else {
            panic!("expected auth gate");
        };
        assert_eq!(first_gate.gate_id, second_gate.gate_id);
        assert!(
            first_gate.gate_id.as_str().starts_with("auth-"),
            "gate id should be stable and auth-specific: {}",
            first_gate.gate_id.as_str()
        );
    }

    #[test]
    fn auth_required_outcome_changes_gate_when_requirements_change() {
        let first = auth_required_outcome(cap(), Vec::new(), vec![auth_requirement(&["read"])]);
        let second = auth_required_outcome(cap(), Vec::new(), vec![auth_requirement(&["write"])]);

        let RuntimeCapabilityOutcome::AuthRequired(first_gate) = first else {
            panic!("expected auth gate");
        };
        let RuntimeCapabilityOutcome::AuthRequired(second_gate) = second else {
            panic!("expected auth gate");
        };
        assert_ne!(first_gate.gate_id, second_gate.gate_id);
    }

    #[test]
    fn dispatch_kind_to_failure_pins_every_runtime_dispatch_error_kind() {
        // Every RuntimeDispatchErrorKind variant must map to a non-Unknown
        // failure kind so upstream additions are surfaced explicitly.
        let cases: &[(RuntimeDispatchErrorKind, RuntimeFailureKind)] = &[
            (
                RuntimeDispatchErrorKind::Backend,
                RuntimeFailureKind::Backend,
            ),
            (
                RuntimeDispatchErrorKind::Client,
                RuntimeFailureKind::Backend,
            ),
            (
                RuntimeDispatchErrorKind::Executor,
                RuntimeFailureKind::Backend,
            ),
            (
                RuntimeDispatchErrorKind::ExitFailure,
                RuntimeFailureKind::Process,
            ),
            (
                RuntimeDispatchErrorKind::ExtensionRuntimeMismatch,
                RuntimeFailureKind::MissingRuntime,
            ),
            (
                RuntimeDispatchErrorKind::FilesystemDenied,
                RuntimeFailureKind::Authorization,
            ),
            (RuntimeDispatchErrorKind::Guest, RuntimeFailureKind::Backend),
            (
                RuntimeDispatchErrorKind::InputEncode,
                RuntimeFailureKind::InvalidInput,
            ),
            (
                RuntimeDispatchErrorKind::InvalidResult,
                RuntimeFailureKind::InvalidOutput,
            ),
            (
                RuntimeDispatchErrorKind::Manifest,
                RuntimeFailureKind::Backend,
            ),
            (
                RuntimeDispatchErrorKind::Memory,
                RuntimeFailureKind::Resource,
            ),
            (
                RuntimeDispatchErrorKind::MethodMissing,
                RuntimeFailureKind::InvalidInput,
            ),
            (
                RuntimeDispatchErrorKind::NetworkDenied,
                RuntimeFailureKind::Network,
            ),
            (
                RuntimeDispatchErrorKind::OperationFailed,
                RuntimeFailureKind::OperationFailed,
            ),
            (
                RuntimeDispatchErrorKind::OutputDecode,
                RuntimeFailureKind::InvalidOutput,
            ),
            (
                RuntimeDispatchErrorKind::OutputTooLarge,
                RuntimeFailureKind::OutputTooLarge,
            ),
            (
                RuntimeDispatchErrorKind::PolicyDenied,
                RuntimeFailureKind::PolicyDenied,
            ),
            (
                RuntimeDispatchErrorKind::Resource,
                RuntimeFailureKind::Resource,
            ),
            (
                RuntimeDispatchErrorKind::SecretDenied,
                RuntimeFailureKind::Authorization,
            ),
            (
                RuntimeDispatchErrorKind::UndeclaredCapability,
                RuntimeFailureKind::InvalidInput,
            ),
            (
                RuntimeDispatchErrorKind::UnsupportedRunner,
                RuntimeFailureKind::Backend,
            ),
            // The fail-safe "uncategorized" redaction bucket collapses to a
            // concrete, surfacing `Internal` rather than a dedicated `Unknown`
            // category (which no longer exists on `RuntimeFailureKind`).
            (
                RuntimeDispatchErrorKind::Unknown,
                RuntimeFailureKind::Internal,
            ),
        ];
        for (variant, expected) in cases {
            let kind = DispatchFailureKind::Runtime(*variant);
            let actual = RuntimeFailureKind::from(kind);
            assert_eq!(
                actual, *expected,
                "dispatch kind {kind:?} should map to {expected:?}, got {actual:?}"
            );
        }
    }

    #[test]
    fn dispatch_kind_to_failure_pins_dispatch_error_top_level_kinds() {
        let cases: &[(DispatchFailureKind, RuntimeFailureKind)] = &[
            (
                DispatchFailureKind::UnknownCapability,
                RuntimeFailureKind::InvalidOutput,
            ),
            (
                DispatchFailureKind::UnknownProvider,
                RuntimeFailureKind::InvalidOutput,
            ),
            (
                DispatchFailureKind::MissingRuntimeBackend,
                RuntimeFailureKind::MissingRuntime,
            ),
            (
                DispatchFailureKind::UnsupportedRuntime,
                RuntimeFailureKind::MissingRuntime,
            ),
            (
                DispatchFailureKind::RuntimeMismatch,
                RuntimeFailureKind::Backend,
            ),
            (
                DispatchFailureKind::AuthRequired,
                RuntimeFailureKind::Authorization,
            ),
        ];
        for (kind, expected) in cases {
            assert_eq!(RuntimeFailureKind::from(*kind), *expected, "kind {kind:?}");
        }
    }

    #[test]
    fn failure_kind_from_dispatch_unknown_capability_maps_to_invalid_output() {
        let error = dispatch(DispatchFailureKind::UnknownCapability);
        assert_eq!(failure_kind_from(&error), RuntimeFailureKind::InvalidOutput);
    }

    #[test]
    fn failure_kind_from_unknown_capability_variant_maps_to_missing_runtime() {
        let error = CapabilityInvocationError::UnknownCapability { capability: cap() };
        assert_eq!(
            failure_kind_from(&error),
            RuntimeFailureKind::MissingRuntime
        );
    }

    #[test]
    fn host_runtime_spawn_input_for_capability_passthrough_for_non_sandbox() {
        let input = serde_json::json!({
            "run": {
                "command": "",
            },
            "other": ["unchanged"],
        });

        let output = host_runtime_spawn_input_for_capability(&cap(), input.clone())
            .expect("non-sandbox capability input should pass through");

        match output {
            SpawnInputPreparation::Ready(value) => assert_eq!(value, input),
            SpawnInputPreparation::ModelInputRejected(_) => {
                panic!("non-sandbox input must pass through unchanged")
            }
        }
    }

    fn process_sandbox_cap() -> CapabilityId {
        CapabilityId::new(PROCESS_SANDBOX_CAPABILITY_ID).expect("valid process sandbox capability")
    }

    #[test]
    fn host_runtime_spawn_input_rejects_malformed_plan_as_recoverable_invalid_input() {
        // The model supplied JSON that is not a `SandboxProcessPlan` at all.
        // This is model-fixable: it must surface as a recoverable, model-visible
        // tool error (`InvalidInput`), never a terminal `HostRuntimeError`.
        let input = serde_json::json!({ "not_run": true });

        let output = host_runtime_spawn_input_for_capability(&process_sandbox_cap(), input)
            .expect("malformed model plan must not be a terminal host error");

        match output {
            SpawnInputPreparation::ModelInputRejected(failure) => {
                assert_eq!(failure.kind, RuntimeFailureKind::InvalidInput);
                assert_eq!(
                    failure.disposition(),
                    crate::CapabilityFailureDisposition::ModelVisibleToolError
                );
            }
            SpawnInputPreparation::Ready(_) => {
                panic!("malformed plan must be rejected as model-visible InvalidInput")
            }
        }
    }

    #[test]
    fn host_runtime_spawn_input_rejects_invalid_plan_as_recoverable_invalid_input() {
        // The model supplied a structurally-parseable plan that fails
        // `ValidatedSandboxProcessPlan` validation (empty command). Still
        // model-fixable → recoverable `InvalidInput`, not terminal.
        let input = serde_json::json!({ "run": { "command": "" } });

        let output = host_runtime_spawn_input_for_capability(&process_sandbox_cap(), input)
            .expect("invalid model plan must not be a terminal host error");

        match output {
            SpawnInputPreparation::ModelInputRejected(failure) => {
                assert_eq!(failure.kind, RuntimeFailureKind::InvalidInput);
                assert_eq!(
                    failure.disposition(),
                    crate::CapabilityFailureDisposition::ModelVisibleToolError
                );
            }
            SpawnInputPreparation::Ready(_) => {
                panic!("invalid plan must be rejected as model-visible InvalidInput")
            }
        }
    }

    #[test]
    fn host_runtime_spawn_input_accepts_valid_plan() {
        let input = serde_json::json!({ "run": { "command": "echo", "args": ["ok"] } });

        let output = host_runtime_spawn_input_for_capability(&process_sandbox_cap(), input)
            .expect("valid plan preparation must not error");

        match output {
            SpawnInputPreparation::Ready(value) => {
                assert!(value.is_object(), "validated plan serializes to an object");
            }
            SpawnInputPreparation::ModelInputRejected(_) => {
                panic!("valid plan must be accepted")
            }
        }
    }

    #[test]
    fn sanitized_failure_message_redacts_dispatch_kind_to_stable_form() {
        let error = dispatch(DispatchFailureKind::Runtime(
            RuntimeDispatchErrorKind::NetworkDenied,
        ));
        let message = sanitized_failure_message(&error).expect("dispatch produces a message");
        // With no host-authored safe_summary, the message is the fixed
        // human-readable summary for the redacted kind — derived only from the
        // category, never from raw backend strings.
        assert_eq!(message, "the tool was denied network access");
    }

    #[test]
    fn sanitized_failure_message_uses_dispatch_safe_summary() {
        let error = CapabilityInvocationError::Dispatch {
            kind: DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::OperationFailed),
            safe_summary: Some(
                "apply_patch failed for path workspace main.rs: old_string matched 0 times"
                    .to_string(),
            ),
            detail: None,
        };

        assert_eq!(
            sanitized_failure_message(&error).as_deref(),
            Some("apply_patch failed for path workspace main.rs: old_string matched 0 times")
        );
    }

    #[test]
    fn sanitized_failure_message_rejects_unsafe_dispatch_safe_summary() {
        let error = CapabilityInvocationError::Dispatch {
            kind: DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::OperationFailed),
            safe_summary: Some("read_file failed for path workspace api_key.txt".to_string()),
            detail: None,
        };

        let message = sanitized_failure_message(&error).expect("dispatch produces a message");
        // The unsafe safe_summary is rejected, so the message falls back to the
        // host-authored human summary for the kind (not the raw category token).
        assert_eq!(message, "the tool operation failed");
        assert!(!message.contains("api_key"));
    }

    #[test]
    fn failure_from_preserves_dispatch_detail() {
        let issue = ironclaw_host_api::DispatchInputIssue::new(
            "schedule.kind",
            ironclaw_host_api::DispatchInputIssueCode::MissingRequired,
        )
        .expected("cron or once");
        let error = CapabilityInvocationError::Dispatch {
            kind: DispatchFailureKind::Runtime(RuntimeDispatchErrorKind::InputEncode),
            safe_summary: Some("trigger_create input failed validation".to_string()),
            detail: Some(ironclaw_host_api::DispatchFailureDetail::InvalidInput {
                issues: vec![issue.clone()],
            }),
        };

        let failure = failure_from(
            error,
            CapabilityId::new("builtin.trigger_create").expect("valid capability id"),
        );

        assert_eq!(failure.kind, RuntimeFailureKind::InvalidInput);
        assert_eq!(
            failure.detail,
            Some(ironclaw_host_api::DispatchFailureDetail::InvalidInput {
                issues: vec![issue]
            })
        );
    }

    #[test]
    fn runtime_failure_kind_as_str_is_stable_snake_case() {
        // Pin the public metric/tracing tokens; renaming any of these is a
        // breaking observability contract change.
        assert_eq!(RuntimeFailureKind::Authorization.as_str(), "authorization");
        assert_eq!(RuntimeFailureKind::Backend.as_str(), "backend");
        assert_eq!(RuntimeFailureKind::Cancelled.as_str(), "cancelled");
        assert_eq!(RuntimeFailureKind::Dispatcher.as_str(), "dispatcher");
        assert_eq!(RuntimeFailureKind::Internal.as_str(), "internal");
        assert_eq!(RuntimeFailureKind::InvalidInput.as_str(), "invalid_input");
        assert_eq!(RuntimeFailureKind::InvalidOutput.as_str(), "invalid_output");
        assert_eq!(
            RuntimeFailureKind::MissingRuntime.as_str(),
            "missing_runtime"
        );
        assert_eq!(RuntimeFailureKind::Network.as_str(), "network");
        assert_eq!(
            RuntimeFailureKind::OperationFailed.as_str(),
            "operation_failed"
        );
        assert_eq!(
            RuntimeFailureKind::OutputTooLarge.as_str(),
            "output_too_large"
        );
        assert_eq!(RuntimeFailureKind::PolicyDenied.as_str(), "policy_denied");
        assert_eq!(RuntimeFailureKind::Process.as_str(), "process");
        assert_eq!(RuntimeFailureKind::Resource.as_str(), "resource");
        assert_eq!(RuntimeFailureKind::Transient.as_str(), "transient");
        assert_eq!(RuntimeFailureKind::Unavailable.as_str(), "unavailable");
    }

    #[test]
    fn capability_failure_disposition_maps_failure_kinds_once() {
        use crate::CapabilityFailureDisposition::*;

        let cases = [
            (RuntimeFailureKind::Authorization, ModelVisibleToolError),
            (RuntimeFailureKind::Backend, RetrySameCall),
            (RuntimeFailureKind::Cancelled, ModelVisibleToolError),
            (RuntimeFailureKind::Dispatcher, ModelVisibleToolError),
            (RuntimeFailureKind::Internal, RetrySameCall),
            (RuntimeFailureKind::InvalidInput, ModelVisibleToolError),
            (RuntimeFailureKind::InvalidOutput, ModelVisibleToolError),
            (RuntimeFailureKind::MissingRuntime, ModelVisibleToolError),
            (RuntimeFailureKind::Network, RetrySameCall),
            (RuntimeFailureKind::OperationFailed, ModelVisibleToolError),
            (RuntimeFailureKind::OutputTooLarge, ModelVisibleToolError),
            (RuntimeFailureKind::PolicyDenied, ModelVisibleToolError),
            (RuntimeFailureKind::Process, ModelVisibleToolError),
            (RuntimeFailureKind::Resource, ModelVisibleToolError),
            (RuntimeFailureKind::Transient, RetrySameCall),
            (RuntimeFailureKind::Unavailable, RetrySameCall),
        ];

        for (kind, expected) in cases {
            assert_eq!(
                crate::capability_failure_disposition(kind),
                expected,
                "{kind:?}"
            );
        }
    }

    #[test]
    fn capability_failure_disposition_retries_retryable_kinds_before_exhaustion() {
        use crate::CapabilityFailureDisposition::*;
        for kind in [
            RuntimeFailureKind::Backend,
            RuntimeFailureKind::Internal,
            RuntimeFailureKind::Network,
            RuntimeFailureKind::Transient,
            RuntimeFailureKind::Unavailable,
        ] {
            assert_eq!(
                crate::capability_failure_disposition(kind),
                RetrySameCall,
                "{kind:?}"
            );
        }
    }

    // ─── capability_credential_requirements unit tests ──────────────────────────
    //
    // These were previously integration tests in host_runtime_services_contract.rs
    // that called the function via `ironclaw_host_runtime::capability_credential_requirements`.
    // They are kept here as unit tests because the function is now `pub(crate)`,
    // making it invisible to external test binaries. Coverage is equivalent.

    fn build_descriptor_for_manifest(
        manifest_toml: &str,
    ) -> ironclaw_host_api::CapabilityDescriptor {
        let manifest = ExtensionManifest::parse(
            manifest_toml,
            ManifestSource::InstalledLocal,
            &HostPortCatalog::empty(),
        )
        .expect("manifest must parse");
        let cap_id = manifest.capabilities[0].id.clone();
        let root =
            VirtualPath::new(format!("/system/extensions/{}", manifest.id.as_str())).unwrap();
        let package = ExtensionPackage::from_manifest(manifest, root).expect("package must build");
        let mut registry = ExtensionRegistry::new();
        registry.insert(package).unwrap();
        registry.get_capability(&cap_id).unwrap().clone()
    }

    /// `capability_credential_requirements` must return exactly the required
    /// `SecretHandle`-source handles declared in the descriptor, filtered to
    /// `required == true`, and must not include `ProductAuthAccount`-source handles.
    ///
    /// Previously `credential_requirements_extraction_matches_descriptor_required_credentials`
    /// in host_runtime_services_contract.rs (moved here because the function is
    /// now `pub(crate)`; coverage is identical).
    #[test]
    fn credential_requirements_extraction_matches_descriptor_required_credentials() {
        const MANIFEST: &str = r#"
schema_version = "reborn.extension_manifest.v2"
id = "script"
name = "Script With Credential"
version = "0.1.0"
description = "Script extension that requires a runtime credential"
trust = "untrusted"

[runtime]
kind = "script"
runner = "sandboxed_process"
command = "echo"
args = []

[[capabilities]]
id = "script.echo"
description = "Echo through Script"
effects = ["dispatch_capability", "use_secret"]
default_permission = "allow"
visibility = "model"
input_schema_ref = "schemas/test/input.v1.json"
output_schema_ref = "schemas/test/output.v1.json"
prompt_doc_ref = "prompts/test.md"

[[capabilities.runtime_credentials]]
handle = "script_api_token"
source = { type = "secret_handle" }
audience = { scheme = "https", host_pattern = "api.example.com" }
target = { type = "header", name = "x-api-key" }
required = true
"#;
        let descriptor = build_descriptor_for_manifest(MANIFEST);

        let (preflight_handles, preflight_reqs) = capability_credential_requirements(&descriptor);

        // The obligation handler iterates `descriptor.runtime_credentials` filtered
        // to `required == true` — verify `capability_credential_requirements` produces
        // the same handles from the same source.
        let expected_handles: Vec<SecretHandle> = descriptor
            .runtime_credentials
            .iter()
            .filter(|cred| cred.required)
            .map(|cred| cred.handle.clone())
            .collect();

        assert_eq!(
            preflight_handles, expected_handles,
            "capability_credential_requirements must return exactly the required handles from the descriptor"
        );
        assert_eq!(preflight_handles.len(), 1, "expected one required handle");
        assert_eq!(
            preflight_handles[0].as_str(),
            "script_api_token",
            "required handle must be script_api_token"
        );
        // The manifest source is `secret_handle` (not `product_auth_account`), so
        // `product_auth_requirement_for` returns None — credential_requirements is empty.
        assert!(
            preflight_reqs.is_empty(),
            "credential_requirements must be empty for secret_handle source (no product_auth_account)"
        );
    }

    /// A capability descriptor with only `required = false` credentials must
    /// produce empty `required_secrets` and `credential_requirements`.
    ///
    /// Previously `credential_requirements_extraction_returns_empty_for_all_optional_credentials`
    /// in host_runtime_services_contract.rs (moved here because the function is now
    /// `pub(crate)`; coverage is identical).
    #[test]
    fn credential_requirements_extraction_returns_empty_for_all_optional_credentials() {
        const MANIFEST: &str = r#"
schema_version = "reborn.extension_manifest.v2"
id = "script"
name = "Script With Optional Credential"
version = "0.1.0"
description = "Script extension with an optional runtime credential"
trust = "untrusted"

[runtime]
kind = "script"
runner = "sandboxed_process"
command = "echo"
args = []

[[capabilities]]
id = "script.echo"
description = "Echo through Script"
effects = ["dispatch_capability", "use_secret"]
default_permission = "allow"
visibility = "model"
input_schema_ref = "schemas/test/input.v1.json"
output_schema_ref = "schemas/test/output.v1.json"
prompt_doc_ref = "prompts/test.md"

[[capabilities.runtime_credentials]]
handle = "optional_api_token"
source = { type = "secret_handle" }
audience = { scheme = "https", host_pattern = "api.example.com" }
target = { type = "header", name = "x-api-key" }
required = false
"#;
        let descriptor = build_descriptor_for_manifest(MANIFEST);

        let (required_secrets, credential_requirements) =
            capability_credential_requirements(&descriptor);

        assert!(
            required_secrets.is_empty(),
            "capability with only optional credentials must produce empty required_secrets; got {required_secrets:?}"
        );
        assert!(
            credential_requirements.is_empty(),
            "capability with only optional credentials must produce empty credential_requirements; got {credential_requirements:?}"
        );
    }

    /// A REQUIRED `product_auth_account`-source credential must NOT be pushed into
    /// `required_secrets` (its handle is only an injection slot that the account
    /// resolver stages later, so a pre-flight `metadata()` probe would false-positive
    /// `AuthRequired` for an already-connected account). It MUST still surface in
    /// `credential_requirements` so the auth payload can describe the product-auth need.
    #[test]
    fn credential_requirements_extraction_excludes_required_product_auth_account() {
        const MANIFEST: &str = r#"
schema_version = "reborn.extension_manifest.v2"
id = "script"
name = "Script With Product-Auth Credential"
version = "0.1.0"
description = "Script extension that requires a product-auth account credential"
trust = "untrusted"

[runtime]
kind = "script"
runner = "sandboxed_process"
command = "echo"
args = []

[[capabilities]]
id = "script.echo"
description = "Echo through Script"
effects = ["dispatch_capability", "use_secret"]
default_permission = "allow"
visibility = "model"
input_schema_ref = "schemas/test/input.v1.json"
output_schema_ref = "schemas/test/output.v1.json"
prompt_doc_ref = "prompts/test.md"

[[capabilities.runtime_credentials]]
handle = "github_runtime_token"
source = { type = "product_auth_account", provider = "github" }
audience = { scheme = "https", host_pattern = "api.github.com" }
target = { type = "header", name = "authorization", prefix = "Bearer " }
required = true
"#;
        let descriptor = build_descriptor_for_manifest(MANIFEST);

        let (required_secrets, credential_requirements) =
            capability_credential_requirements(&descriptor);

        assert!(
            required_secrets.is_empty(),
            "a required product_auth_account credential must be excluded from required_secrets \
             (the slot handle is not a presence-checkable secret); got {required_secrets:?}"
        );
        assert!(
            !credential_requirements.is_empty(),
            "a required product_auth_account credential must still surface in credential_requirements"
        );
    }

    #[test]
    fn runtime_failure_summary_is_bounded_and_blank_messages_are_not_safe() {
        let blank = RuntimeCapabilityFailure::new(
            cap(),
            RuntimeFailureKind::InvalidInput,
            Some("   ".to_string()),
        );
        assert!(blank.safe_summary().is_none());
        assert_eq!(
            blank.disposition(),
            crate::CapabilityFailureDisposition::ModelVisibleToolError
        );

        let long = RuntimeCapabilityFailure::new(
            cap(),
            RuntimeFailureKind::InvalidInput,
            Some("x".repeat(3000)),
        );
        let summary = long.safe_summary().expect("long message is still safe");
        assert_eq!(summary.chars().count(), 512);
        assert!(summary.ends_with("..."));

        let multibyte = RuntimeCapabilityFailure::new(
            cap(),
            RuntimeFailureKind::InvalidInput,
            Some("é".repeat(3000)),
        );
        let summary = multibyte
            .safe_summary()
            .expect("long multibyte message is still safe");
        assert_eq!(summary.chars().count(), 512);
        assert!(summary.ends_with("..."));

        let exact = RuntimeCapabilityFailure::new(
            cap(),
            RuntimeFailureKind::InvalidInput,
            Some("x".repeat(512)),
        );
        assert_eq!(exact.safe_summary(), Some("x".repeat(512)));
    }

    #[test]
    fn unavailable_from_run_state_uses_redacted_reasons() {
        let error = RunStateError::InvalidPath("/private/users/secret/database.sqlite".to_string());
        let host_error = unavailable_from_run_state(error);
        match host_error {
            HostRuntimeError::Unavailable { reason } => {
                assert!(
                    !reason.contains("/private/"),
                    "sanitized reason must not leak filesystem paths, got {reason:?}"
                );
                assert_eq!(reason, "run-state storage path invalid");
            }
            other => panic!("expected Unavailable, got {other:?}"),
        }

        let error = RunStateError::Filesystem("connection refused at /tmp/runstate.db".to_string());
        let host_error = unavailable_from_run_state(error);
        match host_error {
            HostRuntimeError::Unavailable { reason } => {
                assert!(
                    !reason.contains("/tmp"),
                    "sanitized reason must not leak filesystem paths, got {reason:?}"
                );
                assert_eq!(reason, "run-state filesystem unavailable");
            }
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn unavailable_from_process_error_uses_redacted_reasons() {
        let error = ProcessError::InvalidPath("/private/users/secret/processes".to_string());
        let host_error = unavailable_from_process_error(error);
        match host_error {
            HostRuntimeError::Unavailable { reason } => {
                assert!(
                    !reason.contains("/private/"),
                    "sanitized reason must not leak filesystem paths, got {reason:?}"
                );
                assert_eq!(reason, "process storage path invalid");
            }
            other => panic!("expected Unavailable, got {other:?}"),
        }

        let error = ProcessError::Filesystem(FilesystemError::Backend {
            path: VirtualPath::new("/users/user1/processes.db").unwrap(),
            operation: FilesystemOperation::ReadFile,
            reason: "connection refused at /tmp/processes.db".to_string(),
        });
        let host_error = unavailable_from_process_error(error);
        match host_error {
            HostRuntimeError::Unavailable { reason } => {
                assert!(
                    !reason.contains("/tmp"),
                    "sanitized reason must not leak filesystem paths, got {reason:?}"
                );
                assert_eq!(reason, "process filesystem unavailable");
            }
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }
}
