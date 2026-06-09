use serde::{Deserialize, Serialize};

use crate::RebornCompositionProfile;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RebornReadinessState {
    #[default]
    Disabled,
    DevOnly,
    ProductionValidated,
    MigrationDryRunValidated,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornFacadeReadiness {
    pub host_runtime: bool,
    pub turn_coordinator: bool,
    pub product_auth: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornWorkerReadiness {
    pub turn_runner: bool,
    pub trigger_poller: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RebornReadinessDiagnosticStatus {
    Info,
    Warning,
    Blocking,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RebornReadinessDiagnosticReason {
    Disabled,
    DevOnlyProfile,
    Missing,
    LocalOnly,
    Unverified,
    Unsupported,
    #[serde(other)]
    Unknown,
}

/// Stable operator-facing component names.
///
/// The serialized names intentionally use `snake_case` to match the
/// host-runtime production-wiring component vocabulary consumed by readiness
/// diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebornReadinessDiagnosticComponent {
    CompositionProfile,
    RuntimeBackend,
    RuntimePolicy,
    TrustPolicy,
    Filesystem,
    ResourceGovernor,
    ProcessStore,
    ProcessResultStore,
    RunState,
    ApprovalRequests,
    CapabilityLeases,
    EventSink,
    AuditSink,
    SecretStore,
    CredentialAccountStore,
    CredentialSessionStore,
    RuntimeHttpEgress,
    RuntimeProcessPort,
    WasmCredentialProvider,
    ScriptRuntime,
    McpRuntime,
    WasmRuntime,
    FirstPartyRuntime,
    TurnState,
    RunProfileResolver,
    TurnRunWakeNotifier,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornReadinessDiagnostic {
    pub profile: RebornCompositionProfile,
    pub component: RebornReadinessDiagnosticComponent,
    pub reason: RebornReadinessDiagnosticReason,
    pub status: RebornReadinessDiagnosticStatus,
    /// Whether this diagnostic prevents production Reborn traffic exposure.
    ///
    /// `RebornReadiness::state` remains the primary readiness state. This field
    /// lets consumers identify which diagnostics are production blockers when
    /// a profile is disabled, dev-only, or production-shaped but incomplete.
    pub blocks_production: bool,
}

impl RebornReadinessDiagnostic {
    pub fn disabled() -> Self {
        Self {
            profile: RebornCompositionProfile::Disabled,
            component: RebornReadinessDiagnosticComponent::CompositionProfile,
            reason: RebornReadinessDiagnosticReason::Disabled,
            status: RebornReadinessDiagnosticStatus::Blocking,
            blocks_production: true,
        }
    }

    pub fn local_dev() -> Self {
        Self::dev_only_profile(RebornCompositionProfile::LocalDev)
    }

    pub fn local_dev_yolo() -> Self {
        Self::dev_only_profile(RebornCompositionProfile::LocalDevYolo)
    }

    fn dev_only_profile(profile: RebornCompositionProfile) -> Self {
        Self {
            profile,
            component: RebornReadinessDiagnosticComponent::CompositionProfile,
            reason: RebornReadinessDiagnosticReason::DevOnlyProfile,
            status: RebornReadinessDiagnosticStatus::Blocking,
            blocks_production: true,
        }
    }

    pub fn production_blocker(
        profile: RebornCompositionProfile,
        component: RebornReadinessDiagnosticComponent,
        reason: RebornReadinessDiagnosticReason,
    ) -> Self {
        debug_assert!(profile.requires_production_shape());
        Self {
            profile,
            component,
            reason,
            status: RebornReadinessDiagnosticStatus::Blocking,
            blocks_production: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornReadiness {
    pub profile: RebornCompositionProfile,
    pub state: RebornReadinessState,
    pub facades: RebornFacadeReadiness,
    #[serde(default)]
    pub workers: RebornWorkerReadiness,
    #[serde(default)]
    pub diagnostics: Vec<RebornReadinessDiagnostic>,
}

impl Default for RebornReadiness {
    fn default() -> Self {
        Self::disabled()
    }
}

impl RebornReadiness {
    /// Disabled readiness snapshot with its operator-facing diagnostic.
    ///
    /// This is intentionally not `const`: the rich snapshot includes the
    /// diagnostics vector that downstream readiness surfaces consume.
    pub fn disabled() -> Self {
        Self {
            profile: RebornCompositionProfile::Disabled,
            state: RebornReadinessState::Disabled,
            facades: RebornFacadeReadiness {
                host_runtime: false,
                turn_coordinator: false,
                product_auth: false,
            },
            workers: RebornWorkerReadiness {
                turn_runner: false,
                trigger_poller: false,
            },
            diagnostics: vec![RebornReadinessDiagnostic::disabled()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_default_matches_disabled_snapshot() {
        let readiness = RebornReadiness::default();

        assert_eq!(readiness.profile, RebornCompositionProfile::Disabled);
        assert_eq!(readiness.state, RebornReadinessState::Disabled);
        assert_eq!(readiness.diagnostics.len(), 1);
        assert_eq!(
            readiness.diagnostics[0].reason,
            RebornReadinessDiagnosticReason::Disabled
        );
        assert_eq!(
            readiness.diagnostics[0].status,
            RebornReadinessDiagnosticStatus::Blocking
        );
        assert!(readiness.diagnostics[0].blocks_production);
    }

    #[test]
    fn readiness_deserializes_without_workers_for_older_payloads() {
        let readiness: RebornReadiness = serde_json::from_str(
            r#"{
                "profile": "local-dev",
                "state": "dev-only",
                "facades": {
                    "host_runtime": true,
                    "turn_coordinator": true,
                    "product_auth": false
                }
            }"#,
        )
        .expect("readiness deserializes");

        assert_eq!(readiness.profile, RebornCompositionProfile::LocalDev);
        assert_eq!(readiness.state, RebornReadinessState::DevOnly);
        assert_eq!(readiness.workers, RebornWorkerReadiness::default());
        assert!(readiness.diagnostics.is_empty());
    }
}
