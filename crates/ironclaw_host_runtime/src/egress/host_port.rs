use std::sync::Arc;

use async_trait::async_trait;
use ironclaw_capabilities::{
    CapabilityObligationHandler, CapabilityObligationPhase, CapabilityObligationRequest,
};
use ironclaw_host_api::{
    CapabilityId, CapabilitySet, ExecutionContext, ExtensionId, MountView, NetworkPolicy,
    Obligation, ResourceEstimate, ResourceScope, RuntimeCredentialInjection,
    RuntimeCredentialSource, RuntimeCredentialTarget, RuntimeHttpEgress, RuntimeHttpEgressError,
    RuntimeHttpEgressRequest, RuntimeHttpEgressResponse, RuntimeKind, SecretHandle, TrustClass,
};
use ironclaw_secrets::SecretMaterial;

use crate::obligations::RuntimeSecretInjectionStore;

/// Canonical host-runtime one-shot secret material staging port.
///
/// This is for host-owned adapters that already hold trusted secret material
/// and need the shared runtime HTTP egress to inject it without exposing the
/// material through request headers.
#[derive(Clone)]
pub struct RuntimeSecretMaterialStager {
    secret_injection_store: Arc<RuntimeSecretInjectionStore>,
}

/// Alias for [`ironclaw_host_api::CredentialStageError`].
pub type RuntimeSecretStageError = ironclaw_host_api::CredentialStageError;

impl RuntimeSecretMaterialStager {
    pub(crate) fn new(secret_injection_store: Arc<RuntimeSecretInjectionStore>) -> Self {
        Self {
            secret_injection_store,
        }
    }

    pub async fn stage_secret_material_once(
        &self,
        target_scope: &ResourceScope,
        capability_id: &CapabilityId,
        handle: &SecretHandle,
        material: SecretMaterial,
    ) -> Result<(), RuntimeSecretStageError> {
        self.secret_injection_store
            .insert(target_scope, capability_id, handle, material)
            .map_err(|_| RuntimeSecretStageError::Backend)
    }

    fn discard_secret_material_for_capability(
        &self,
        target_scope: &ResourceScope,
        capability_id: &CapabilityId,
    ) {
        if let Err(error) = self
            .secret_injection_store
            .discard_for_capability(target_scope, capability_id)
        {
            tracing::debug!(
                error = ?error,
                capability_id = %capability_id,
                "host HTTP egress failed to discard staged secret material"
            );
        }
    }
}

#[derive(Clone)]
pub struct HostRuntimeHttpEgressPort {
    runtime_http_egress: Arc<dyn RuntimeHttpEgress>,
    obligation_handler: Arc<dyn CapabilityObligationHandler>,
    secret_stager: RuntimeSecretMaterialStager,
}

pub struct HostRuntimeHttpEgressRequest {
    pub extension_id: ExtensionId,
    pub trust: TrustClass,
    pub request: RuntimeHttpEgressRequest,
    pub credentials: Vec<HostRuntimeCredentialMaterial>,
}

pub struct HostRuntimeCredentialMaterial {
    pub handle: SecretHandle,
    pub material: SecretMaterial,
    pub target: RuntimeCredentialTarget,
    pub required: bool,
}

/// Identity + scope for staging a host-initiated request's invoke-phase
/// obligations. Bundles the five values that always travel together to build
/// the [`ExecutionContext`] and key the staged obligations, so the staging
/// entry points stay within one argument budget and read as one concept.
pub struct HostInitiatedInvokeContext<'a> {
    pub extension_id: ExtensionId,
    pub trust: TrustClass,
    pub runtime: RuntimeKind,
    pub scope: &'a ResourceScope,
    pub capability_id: &'a CapabilityId,
}

impl HostRuntimeHttpEgressPort {
    pub(crate) fn new(
        runtime_http_egress: Arc<dyn RuntimeHttpEgress>,
        obligation_handler: Arc<dyn CapabilityObligationHandler>,
        secret_stager: RuntimeSecretMaterialStager,
    ) -> Self {
        Self {
            runtime_http_egress,
            obligation_handler,
            secret_stager,
        }
    }

    pub async fn execute(
        &self,
        mut request: HostRuntimeHttpEgressRequest,
    ) -> Result<RuntimeHttpEgressResponse, RuntimeHttpEgressError> {
        if !request.request.credential_injections.is_empty() {
            return Err(RuntimeHttpEgressError::Credential {
                reason: "host-mediated HTTP egress does not accept caller-provided credential injections"
                    .to_string(),
            });
        }
        self.authorize_network_egress(&request).await?;
        let staged_scope = request.request.scope.clone();
        let staged_capability_id = request.request.capability_id.clone();
        let staged_credentials = !request.credentials.is_empty();
        if let Err(error) = self
            .stage_credentials(&mut request.request, request.credentials)
            .await
        {
            if staged_credentials {
                self.secret_stager
                    .discard_secret_material_for_capability(&staged_scope, &staged_capability_id);
            }
            return Err(error);
        }
        let result = self.runtime_http_egress.execute(request.request).await;
        if staged_credentials {
            self.secret_stager
                .discard_secret_material_for_capability(&staged_scope, &staged_capability_id);
        }
        result
    }

    async fn stage_credentials(
        &self,
        request: &mut RuntimeHttpEgressRequest,
        credentials: Vec<HostRuntimeCredentialMaterial>,
    ) -> Result<(), RuntimeHttpEgressError> {
        for credential in credentials {
            self.secret_stager
                .stage_secret_material_once(
                    &request.scope,
                    &request.capability_id,
                    &credential.handle,
                    credential.material,
                )
                .await
                .map_err(|_| RuntimeHttpEgressError::Credential {
                    reason: "host credential material could not be staged".to_string(),
                })?;
            request
                .credential_injections
                .push(RuntimeCredentialInjection {
                    handle: credential.handle,
                    source: RuntimeCredentialSource::StagedObligation {
                        capability_id: request.capability_id.clone(),
                    },
                    target: credential.target,
                    required: credential.required,
                });
        }
        Ok(())
    }

    async fn authorize_network_egress(
        &self,
        request: &HostRuntimeHttpEgressRequest,
    ) -> Result<(), RuntimeHttpEgressError> {
        let policy = request.request.network_policy.clone();
        self.stage_invoke_obligations(
            HostInitiatedInvokeContext {
                extension_id: request.extension_id.clone(),
                trust: request.trust,
                runtime: request.request.runtime,
                scope: &request.request.scope,
                capability_id: &request.request.capability_id,
            },
            policy.max_egress_bytes,
            &[Obligation::ApplyNetworkPolicy { policy }],
        )
        .await
    }

    /// Stages BOTH the host [`Obligation::ApplyNetworkPolicy`] AND the one-shot
    /// secret material for a host-initiated request whose credential injections
    /// resolve through `RuntimeCredentialSource::StagedObligation`.
    ///
    /// Capability dispatch stages `ApplyNetworkPolicy` (from the grant's
    /// network constraints) AND `InjectSecretOnce` (leasing the agent's secret
    /// from the store) before the runtime lane runs; the shared egress reads
    /// both back. Host-initiated requests that never flow through dispatch —
    /// hosted-MCP per-user discovery is the motivating case — have nothing to
    /// stage either, so the shared egress reads an empty policy (fails
    /// `network_error`, internally `network_policy_missing`) and, once the
    /// policy is staged, an unresolved credential injection (fails
    /// `credential_unavailable`). This stages the policy plus one
    /// `InjectSecretOnce` per handle, so the same `inject_secrets` path (with
    /// Kolya's owner-scope secret fallback, `resolve_present_secret_scope`)
    /// leases the material into the store the egress reads. Staging is atomic:
    /// a missing/failed secret aborts the whole obligation set (nothing is
    /// staged) and the caller fails closed — hosted-MCP discovery maps that to
    /// serving the static floor.
    pub async fn stage_network_policy_and_secret_injections(
        &self,
        context: HostInitiatedInvokeContext<'_>,
        policy: NetworkPolicy,
        secret_handles: &[SecretHandle],
    ) -> Result<(), RuntimeHttpEgressError> {
        let max_egress_bytes = policy.max_egress_bytes;
        let mut obligations = Vec::with_capacity(1 + secret_handles.len());
        obligations.push(Obligation::ApplyNetworkPolicy { policy });
        for handle in secret_handles {
            obligations.push(Obligation::InjectSecretOnce {
                handle: handle.clone(),
            });
        }
        self.stage_invoke_obligations(context, max_egress_bytes, &obligations)
            .await
    }

    async fn stage_invoke_obligations(
        &self,
        context: HostInitiatedInvokeContext<'_>,
        network_egress_bytes: Option<u64>,
        obligations: &[Obligation],
    ) -> Result<(), RuntimeHttpEgressError> {
        let execution_context = execution_context_for_host_http_egress(
            context.scope,
            context.extension_id,
            context.runtime,
            context.trust,
        )?;
        let estimate = ResourceEstimate {
            network_egress_bytes,
            ..ResourceEstimate::default()
        };
        self.obligation_handler
            .satisfy(CapabilityObligationRequest {
                phase: CapabilityObligationPhase::Invoke,
                context: &execution_context,
                capability_id: context.capability_id,
                estimate: &estimate,
                obligations,
            })
            .await
            .map_err(|error| RuntimeHttpEgressError::Request {
                reason: format!("host egress obligations were not authorized: {error}"),
                request_bytes: 0,
                response_bytes: 0,
            })
    }

    /// The shared runtime HTTP egress this port stages obligations for.
    pub fn runtime_http_egress(&self) -> Arc<dyn RuntimeHttpEgress> {
        Arc::clone(&self.runtime_http_egress)
    }

    /// Adapts this port into a plain [`RuntimeHttpEgress`] for host-initiated
    /// requests from a single extension (identity + trust fixed here rather
    /// than carried on each [`RuntimeHttpEgressRequest`]). Each `execute`
    /// stages the request-carried network policy AND the one-shot secret
    /// material for its `StagedObligation` credential injections through
    /// [`Self::stage_network_policy_and_secret_injections`], then delegates to
    /// the shared egress, which reads both back — mirroring how dispatch
    /// stages `ApplyNetworkPolicy` + `InjectSecretOnce` for a normal
    /// capability call.
    pub fn into_host_initiated_egress(
        self,
        extension_id: ExtensionId,
        trust: TrustClass,
    ) -> Arc<dyn RuntimeHttpEgress> {
        Arc::new(HostInitiatedHttpEgress {
            port: self,
            extension_id,
            trust,
        })
    }
}

/// A [`RuntimeHttpEgress`] for host-initiated requests (hosted-MCP per-user
/// discovery) that stages the request-carried network policy AND the secret
/// material its `StagedObligation` credential injections need, before
/// delegating to the shared runtime egress. Constructed via
/// [`HostRuntimeHttpEgressPort::into_host_initiated_egress`].
struct HostInitiatedHttpEgress {
    port: HostRuntimeHttpEgressPort,
    extension_id: ExtensionId,
    trust: TrustClass,
}

#[async_trait]
impl RuntimeHttpEgress for HostInitiatedHttpEgress {
    async fn execute(
        &self,
        request: RuntimeHttpEgressRequest,
    ) -> Result<RuntimeHttpEgressResponse, RuntimeHttpEgressError> {
        // The egress resolves each `StagedObligation` injection from the
        // staged-secret store keyed by (scope, this request's capability_id);
        // stage `InjectSecretOnce` for exactly those handles so dispatch and
        // discovery lease the same material the same way. De-duplicate: one
        // handle may back several injection targets in a single request, but
        // `InjectSecretOnce` leases it once.
        let mut secret_handles: Vec<SecretHandle> = Vec::new();
        for injection in &request.credential_injections {
            if let RuntimeCredentialSource::StagedObligation { capability_id } = &injection.source
                && capability_id == &request.capability_id
                && !secret_handles.contains(&injection.handle)
            {
                secret_handles.push(injection.handle.clone());
            }
        }
        self.port
            .stage_network_policy_and_secret_injections(
                HostInitiatedInvokeContext {
                    extension_id: self.extension_id.clone(),
                    trust: self.trust,
                    runtime: request.runtime,
                    scope: &request.scope,
                    capability_id: &request.capability_id,
                },
                request.network_policy.clone(),
                &secret_handles,
            )
            .await?;
        self.port.runtime_http_egress().execute(request).await
    }
}

fn execution_context_for_host_http_egress(
    scope: &ResourceScope,
    extension_id: ExtensionId,
    runtime: RuntimeKind,
    trust: TrustClass,
) -> Result<ExecutionContext, RuntimeHttpEgressError> {
    let context = ExecutionContext {
        invocation_id: scope.invocation_id,
        correlation_id: ironclaw_host_api::CorrelationId::new(),
        process_id: None,
        parent_process_id: None,
        tenant_id: scope.tenant_id.clone(),
        user_id: scope.user_id.clone(),
        agent_id: scope.agent_id.clone(),
        project_id: scope.project_id.clone(),
        mission_id: scope.mission_id.clone(),
        thread_id: scope.thread_id.clone(),
        extension_id,
        runtime,
        trust,
        grants: CapabilitySet::default(),
        mounts: MountView::default(),
        resource_scope: scope.clone(),
    };
    context
        .validate()
        .map_err(|error| RuntimeHttpEgressError::Credential {
            reason: format!("invalid host HTTP egress context: {error}"),
        })?;
    Ok(context)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use ironclaw_capabilities::{
        CapabilityObligationError, CapabilityObligationFailureKind, CapabilityObligationRequest,
    };
    use ironclaw_host_api::{
        InvocationId, NetworkMethod, NetworkPolicy, NetworkScheme, NetworkTargetPattern,
        RuntimeHttpEgressResponse, UserId,
    };

    use super::*;

    struct AllowObligations;

    #[async_trait]
    impl CapabilityObligationHandler for AllowObligations {
        async fn satisfy(
            &self,
            _request: CapabilityObligationRequest<'_>,
        ) -> Result<(), CapabilityObligationError> {
            Ok(())
        }
    }

    struct DenyNetworkObligations;

    #[async_trait]
    impl CapabilityObligationHandler for DenyNetworkObligations {
        async fn satisfy(
            &self,
            _request: CapabilityObligationRequest<'_>,
        ) -> Result<(), CapabilityObligationError> {
            Err(CapabilityObligationError::Failed {
                kind: CapabilityObligationFailureKind::Network,
            })
        }
    }

    struct RecordingRuntimeHttpEgress {
        calls: AtomicUsize,
        response: Result<RuntimeHttpEgressResponse, RuntimeHttpEgressError>,
    }

    impl RecordingRuntimeHttpEgress {
        fn ok() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                response: Ok(RuntimeHttpEgressResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: Vec::new(),
                    saved_body: None,
                    request_bytes: 0,
                    response_bytes: 0,
                    redaction_applied: false,
                }),
            }
        }

        fn failing() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                response: Err(RuntimeHttpEgressError::Network {
                    reason: "network_error".to_string(),
                    request_bytes: 17,
                    response_bytes: 0,
                }),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl RuntimeHttpEgress for RecordingRuntimeHttpEgress {
        async fn execute(
            &self,
            _request: RuntimeHttpEgressRequest,
        ) -> Result<RuntimeHttpEgressResponse, RuntimeHttpEgressError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.response.clone()
        }
    }

    #[tokio::test]
    async fn host_runtime_http_egress_rejects_caller_provided_credential_injections() {
        let egress = Arc::new(RecordingRuntimeHttpEgress::ok());
        let port = host_port(egress.clone(), Arc::new(AllowObligations), secret_store());
        let mut request = host_request();
        request
            .request
            .credential_injections
            .push(RuntimeCredentialInjection {
                handle: secret_handle(),
                source: RuntimeCredentialSource::StagedObligation {
                    capability_id: capability_id(),
                },
                target: RuntimeCredentialTarget::Header {
                    name: "authorization".to_string(),
                    prefix: Some("Bearer ".to_string()),
                },
                required: true,
            });

        let error = port
            .execute(request)
            .await
            .expect_err("caller-provided credential injections must be rejected");

        assert!(matches!(error, RuntimeHttpEgressError::Credential { .. }));
        assert_eq!(egress.calls(), 0);
    }

    #[tokio::test]
    async fn host_runtime_http_egress_maps_network_policy_denial_to_request_error() {
        let egress = Arc::new(RecordingRuntimeHttpEgress::ok());
        let port = host_port(
            egress.clone(),
            Arc::new(DenyNetworkObligations),
            secret_store(),
        );

        let error = port
            .execute(host_request())
            .await
            .expect_err("policy denial must fail before runtime egress");

        assert!(matches!(error, RuntimeHttpEgressError::Request { .. }));
        assert_eq!(error.stable_runtime_reason(), "request_denied");
        assert_eq!(egress.calls(), 0);
    }

    #[tokio::test]
    async fn host_runtime_http_egress_discards_staged_secret_after_delegate_failure() {
        let store = secret_store();
        let egress = Arc::new(RecordingRuntimeHttpEgress::failing());
        let port = host_port(egress, Arc::new(AllowObligations), Arc::clone(&store));
        let mut request = host_request();
        let scope = request.request.scope.clone();
        let capability_id = request.request.capability_id.clone();
        let handle = secret_handle();
        request.credentials.push(HostRuntimeCredentialMaterial {
            handle: handle.clone(),
            material: SecretMaterial::from("host-held-token"),
            target: RuntimeCredentialTarget::Header {
                name: "authorization".to_string(),
                prefix: Some("Bearer ".to_string()),
            },
            required: true,
        });

        let error = port
            .execute(request)
            .await
            .expect_err("delegate egress failure should bubble");

        assert!(matches!(error, RuntimeHttpEgressError::Network { .. }));
        assert!(
            store
                .take(&scope, &capability_id, &handle)
                .expect("staged secret store should be readable")
                .is_none(),
            "host-staged material should be discarded after delegate failure"
        );
    }

    fn host_port(
        egress: Arc<dyn RuntimeHttpEgress>,
        obligations: Arc<dyn CapabilityObligationHandler>,
        store: Arc<RuntimeSecretInjectionStore>,
    ) -> HostRuntimeHttpEgressPort {
        HostRuntimeHttpEgressPort::new(egress, obligations, RuntimeSecretMaterialStager::new(store))
    }

    fn host_request() -> HostRuntimeHttpEgressRequest {
        HostRuntimeHttpEgressRequest {
            extension_id: ExtensionId::new("test_extension").expect("extension id"),
            trust: TrustClass::System,
            request: RuntimeHttpEgressRequest {
                runtime: RuntimeKind::FirstParty,
                scope: scope(),
                capability_id: capability_id(),
                method: NetworkMethod::Get,
                url: "https://api.example.test/v1".to_string(),
                headers: Vec::new(),
                body: Vec::new(),
                network_policy: network_policy(),
                credential_injections: Vec::new(),
                response_body_limit: None,
                save_body_to: None,
                timeout_ms: None,
            },
            credentials: Vec::new(),
        }
    }

    fn scope() -> ResourceScope {
        ResourceScope::local_default(
            UserId::new("user:test").expect("user id"),
            InvocationId::new(),
        )
        .expect("scope")
    }

    fn capability_id() -> CapabilityId {
        CapabilityId::new("test.host_http").expect("capability id")
    }

    fn secret_handle() -> SecretHandle {
        SecretHandle::new("host-held-token").expect("secret handle")
    }

    fn secret_store() -> Arc<RuntimeSecretInjectionStore> {
        Arc::new(RuntimeSecretInjectionStore::new())
    }

    fn network_policy() -> NetworkPolicy {
        NetworkPolicy {
            allowed_targets: vec![NetworkTargetPattern {
                scheme: Some(NetworkScheme::Https),
                host_pattern: "api.example.test".to_string(),
                port: None,
            }],
            deny_private_ip_ranges: true,
            max_egress_bytes: Some(1024),
        }
    }
}
