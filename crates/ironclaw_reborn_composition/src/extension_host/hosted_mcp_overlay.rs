//! Composition-owned [`HostedMcpSurfaceOverlay`] implementation.
//!
//! Fetches the live per-hire hosted-MCP tool surface by reusing
//! [`discover_hosted_mcp_package`] against the hire's own owner scope (never
//! the global registry), with a per-(hire, package) TTL cache and
//! single-flight collapse so concurrent turns for the same hire/package do
//! not each pay a `tools/list` round trip. See
//! `crates/ironclaw_host_runtime/src/hosted_mcp_overlay.rs` for the trait
//! contract and the [`HireScope`] leak gate this relies on.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex as StdMutex, PoisonError},
    time::Duration,
};

use async_trait::async_trait;
use ironclaw_extensions::ExtensionPackage;
use ironclaw_host_api::{
    AgentId, CapabilityDescriptor, ExtensionId, ProjectId, RuntimeHttpEgress, TenantId, UserId,
};
use ironclaw_host_runtime::{HireScope, HostedMcpOverlayError, HostedMcpSurfaceOverlay};
use tokio::sync::Mutex as AsyncMutex;
// `tokio::time::Instant`, not `std::time::Instant`: cache-entry timestamps
// must observe `tokio::time::pause`/`advance` under `start_paused = true`
// tests (see `overlay_refetches_after_ttl_expiry`), and behave identically
// to `std::time::Instant` outside of a paused-clock test runtime.
use tokio::time::Instant;

use crate::extension_host::mcp_discovery::{HostedMcpDiscoveryError, discover_hosted_mcp_package};

/// TTL a successful discovery result stays cached per (hire, package).
const OVERLAY_CACHE_TTL: Duration = Duration::from_secs(60);
/// Safety-net cap on distinct cache entries. Bounded in practice by active
/// hire agents times hosted-mcp packages; this is the backstop, not the
/// normal operating limit.
const MAX_OVERLAY_CACHE_ENTRIES: usize = 4096;

/// Cache/single-flight identity for one (hire owner, package) pair.
///
/// Deliberately built from the explicit identity fields, NOT `hire.clone()`
/// — `HireScope` also carries `invocation_id` (needed for the discovery
/// lease call, see `HireScope::to_owner_scope`), which is fresh on every
/// claimed run. Embedding the whole `HireScope` here would make every
/// resumed/retried run on the same agent a cold cache miss, defeating the
/// TTL cache and single-flight collapse across turns — the entire point of
/// this cache. `agent_id` (plus tenant/user/project) is the real identity
/// boundary; `invocation_id` is not.
#[derive(Clone, PartialEq, Eq, Hash)]
struct OverlayCacheKey {
    tenant_id: TenantId,
    user_id: UserId,
    agent_id: AgentId,
    project_id: Option<ProjectId>,
    extension_id: ExtensionId,
    manifest_digest: Option<String>,
}

impl OverlayCacheKey {
    fn new(hire: &HireScope, package: &ExtensionPackage) -> Self {
        Self {
            tenant_id: hire.tenant_id().clone(),
            user_id: hire.user_id().clone(),
            agent_id: hire.agent_id().clone(),
            project_id: hire.project_id().cloned(),
            extension_id: package.id.clone(),
            manifest_digest: package.manifest_digest(),
        }
    }
}

struct CacheEntry {
    fetched_at: Instant,
    descriptors: Arc<Vec<CapabilityDescriptor>>,
}

type InflightMap = HashMap<OverlayCacheKey, Arc<AsyncMutex<()>>>;

/// Composition-owned [`HostedMcpSurfaceOverlay`]. One instance is shared
/// across every turn (constructed once in `factory::attach_hosted_mcp_overlay`
/// and injected into [`ironclaw_host_runtime::services::HostRuntimeServices`]),
/// so the cache and single-flight map are process-wide, not per-request.
///
/// `inflight` is a `std::sync::Mutex`, not `tokio::sync::Mutex`, because its
/// cleanup runs from [`InflightCleanupGuard`]'s `Drop` impl, which cannot
/// take an async lock. `store`'s critical sections never span an `.await`
/// either, but it stays `tokio::sync::Mutex` for consistency with the rest
/// of the async surface.
pub(crate) struct CompositionHostedMcpOverlay {
    runtime_http_egress: Arc<dyn RuntimeHttpEgress>,
    store: AsyncMutex<HashMap<OverlayCacheKey, CacheEntry>>,
    inflight: Arc<StdMutex<InflightMap>>,
}

impl CompositionHostedMcpOverlay {
    pub(crate) fn new(runtime_http_egress: Arc<dyn RuntimeHttpEgress>) -> Self {
        Self {
            runtime_http_egress,
            store: AsyncMutex::new(HashMap::new()),
            inflight: Arc::new(StdMutex::new(HashMap::new())),
        }
    }

    /// Reads the cache, evicting the entry in place if it has expired.
    async fn cached(&self, key: &OverlayCacheKey) -> Option<Arc<Vec<CapabilityDescriptor>>> {
        let mut store = self.store.lock().await;
        match store.get(key) {
            Some(entry) if entry.fetched_at.elapsed() < OVERLAY_CACHE_TTL => {
                Some(Arc::clone(&entry.descriptors))
            }
            Some(_) => {
                store.remove(key);
                None
            }
            None => None,
        }
    }

    async fn insert(&self, key: OverlayCacheKey, descriptors: Arc<Vec<CapabilityDescriptor>>) {
        let mut store = self.store.lock().await;
        if store.len() >= MAX_OVERLAY_CACHE_ENTRIES && !store.contains_key(&key) {
            let oldest = store
                .iter()
                .min_by_key(|(_, entry)| entry.fetched_at)
                .map(|(oldest_key, _)| oldest_key.clone());
            if let Some(oldest) = oldest {
                store.remove(&oldest);
            }
        }
        store.insert(
            key,
            CacheEntry {
                fetched_at: Instant::now(),
                descriptors,
            },
        );
    }

    /// Gets or creates this key's single-flight guard and acquires it,
    /// returning a cancel-safe cleanup guard. Unlike an explicit
    /// "release" call at the end of the function, this guard's `Drop`
    /// impl runs on EVERY exit path — normal return, early return, AND
    /// the surrounding `tokio::time::timeout` in `surface.rs` dropping
    /// this future mid-`.await` on budget elapse — so the `inflight`
    /// entry cannot be orphaned by cancellation.
    fn acquire_inflight(&self, key: &OverlayCacheKey) -> InflightAcquire {
        let per_key = {
            let mut inflight = self.inflight.lock().unwrap_or_else(PoisonError::into_inner);
            Arc::clone(
                inflight
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(AsyncMutex::new(()))),
            )
        };
        InflightAcquire {
            inflight: Arc::clone(&self.inflight),
            key: key.clone(),
            per_key,
        }
    }
}

/// Holds the per-key single-flight `Arc` long enough to lock it; the actual
/// lock+cleanup guard is [`InflightCleanupGuard`], produced by
/// [`InflightAcquire::lock`].
struct InflightAcquire {
    inflight: Arc<StdMutex<InflightMap>>,
    key: OverlayCacheKey,
    per_key: Arc<AsyncMutex<()>>,
}

impl InflightAcquire {
    async fn lock(self) -> InflightCleanupGuard {
        let permit = Arc::clone(&self.per_key).lock_owned().await;
        InflightCleanupGuard {
            inflight: self.inflight,
            key: self.key,
            per_key: self.per_key,
            permit: Some(permit),
        }
    }
}

/// RAII guard held across the double-checked cache read and the discovery
/// call. Its `Drop` impl removes this key's `inflight` entry, but only if
/// no other waiter cloned it while this guard was alive (a strong count of
/// 2 means exactly the map's own reference plus this guard's `per_key`
/// clone — see N2 in the implementation handoff). The permit is released
/// FIRST (`self.permit.take()`), before the strong-count check, so the
/// guard's own `OwnedMutexGuard` (which internally holds another `Arc`
/// clone) doesn't inflate the count against itself.
struct InflightCleanupGuard {
    inflight: Arc<StdMutex<InflightMap>>,
    key: OverlayCacheKey,
    per_key: Arc<AsyncMutex<()>>,
    permit: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Drop for InflightCleanupGuard {
    fn drop(&mut self) {
        // Release the per-key lock before checking the strong count so this
        // guard's own OwnedMutexGuard reference isn't counted.
        self.permit.take();
        let mut inflight = self.inflight.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(current) = inflight.get(&self.key)
            && Arc::ptr_eq(current, &self.per_key)
            && Arc::strong_count(current) <= 2
        {
            inflight.remove(&self.key);
        }
    }
}

#[async_trait]
impl HostedMcpSurfaceOverlay for CompositionHostedMcpOverlay {
    async fn overlay_capabilities(
        &self,
        hire: &HireScope,
        package: &ExtensionPackage,
    ) -> Result<Vec<CapabilityDescriptor>, HostedMcpOverlayError> {
        // follow-up: every cache hit below pays `(*descriptors).clone()`
        // here PLUS a per-descriptor clone in `surface.rs`'s
        // `evaluate_descriptor -> surface_descriptor`. Returning
        // `Arc<Vec<CapabilityDescriptor>>` (or `Arc<[CapabilityDescriptor]>`)
        // through the `HostedMcpSurfaceOverlay` trait would remove the first
        // clone; deferred as a trait-signature change, not done here (perf
        // review: not fatal, the turn's LLM round trip dwarfs it).
        let key = OverlayCacheKey::new(hire, package);
        if let Some(descriptors) = self.cached(&key).await {
            return Ok((*descriptors).clone());
        }

        let _cleanup = self.acquire_inflight(&key).lock().await;

        // Double-checked re-read: a concurrent turn for the same (hire,
        // package) may have populated the cache while we waited for the
        // per-key guard. This is what collapses the herd instead of merely
        // serializing it.
        if let Some(descriptors) = self.cached(&key).await {
            return Ok((*descriptors).clone());
        }

        let result = discover_hosted_mcp_package(
            package,
            hire.to_owner_scope(),
            Arc::clone(&self.runtime_http_egress),
        )
        .await;
        match result {
            Ok(discovered) => {
                let descriptors = Arc::new(discovered.capabilities);
                // Insert BEFORE `_cleanup` drops (end of scope) so a waiter
                // unblocked by the release observes the populated cache on
                // its own double-checked re-read, rather than racing a
                // duplicate fetch.
                self.insert(key, Arc::clone(&descriptors)).await;
                Ok((*descriptors).clone())
            }
            Err(error) => Err(overlay_error_from_discovery(error)),
        }
        // `_cleanup` drops here on every path above, including if this
        // future itself is dropped mid-`.await` by an outer cancellation
        // (e.g. `surface.rs`'s budget timeout) — Rust always runs live
        // locals' `Drop` impls when a `Future` is dropped mid-poll.
    }
}

fn overlay_error_from_discovery(error: HostedMcpDiscoveryError) -> HostedMcpOverlayError {
    match error {
        HostedMcpDiscoveryError::Transient(reason) => HostedMcpOverlayError::Transient(reason),
        HostedMcpDiscoveryError::Permanent(reason) => HostedMcpOverlayError::Permanent(reason),
    }
}

#[cfg(test)]
mod tests {
    use ironclaw_extensions::{ExtensionManifest, ManifestSource};
    use ironclaw_host_api::{
        HostPortCatalog, InvocationId, NetworkMethod, ResourceScope, RuntimeHttpEgressError,
        RuntimeHttpEgressRequest, RuntimeHttpEgressResponse, VirtualPath,
    };

    use super::*;
    use crate::extension_host::hosted_mcp_test_support::HostedMcpDiscoveryEgress;

    const NOTION_MANIFEST: &str = r#"
schema_version = "reborn.extension_manifest.v2"
id = "notion"
name = "Notion"
version = "1.0.0"
description = "Hosted Notion MCP"
trust = "third_party"

[runtime]
kind = "mcp"
transport = "http"
url = "https://mcp.notion.com/mcp"

[[capabilities]]
id = "notion.notion-fetch"
description = "Fetch a Notion page"
effects = ["dispatch_capability", "network", "use_secret"]
default_permission = "ask"
visibility = "model"
input_schema_ref = "schemas/notion/fetch.input.json"
output_schema_ref = "schemas/notion/fetch.output.json"
"#;

    fn notion_package() -> ExtensionPackage {
        let manifest = ExtensionManifest::parse(
            NOTION_MANIFEST,
            ManifestSource::HostBundled,
            &HostPortCatalog::default(),
        )
        .expect("valid Notion manifest");
        ExtensionPackage::from_manifest(
            manifest,
            VirtualPath::new("/system/extensions/notion").expect("valid root"),
        )
        .expect("valid Notion package")
    }

    fn hire(agent: &str) -> HireScope {
        let scope = ResourceScope {
            tenant_id: TenantId::new("acme").unwrap(),
            user_id: UserId::new("buyer-1").unwrap(),
            agent_id: Some(AgentId::new(agent).unwrap()),
            project_id: Some(ProjectId::new("proj-1").unwrap()),
            mission_id: None,
            thread_id: None,
            invocation_id: InvocationId::new(),
        };
        HireScope::from_scope(&scope).expect("agent present")
    }

    #[tokio::test]
    async fn overlay_returns_discovered_descriptors_with_inline_schema() {
        let overlay =
            CompositionHostedMcpOverlay::new(Arc::new(HostedMcpDiscoveryEgress::default()));
        let package = notion_package();

        let descriptors = overlay
            .overlay_capabilities(&hire("agent-1"), &package)
            .await
            .expect("discovery succeeds");

        assert_eq!(descriptors.len(), 1);
        assert_eq!(descriptors[0].id.as_str(), "notion.live-search");
        assert!(descriptors[0].parameters_schema.get("$ref").is_none());
    }

    #[tokio::test]
    async fn overlay_caches_and_does_not_refetch_within_ttl() {
        let egress = Arc::new(HostedMcpDiscoveryEgress::default());
        let overlay =
            CompositionHostedMcpOverlay::new(Arc::clone(&egress) as Arc<dyn RuntimeHttpEgress>);
        let package = notion_package();
        let hire = hire("agent-1");

        overlay
            .overlay_capabilities(&hire, &package)
            .await
            .expect("first discovery succeeds");
        let first_call_count = egress.methods().len();
        overlay
            .overlay_capabilities(&hire, &package)
            .await
            .expect("second call served from cache");

        assert_eq!(
            egress.methods().len(),
            first_call_count,
            "cached result must not trigger another tools/list round trip"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn overlay_refetches_after_ttl_expiry() {
        let egress = Arc::new(HostedMcpDiscoveryEgress::default());
        let overlay =
            CompositionHostedMcpOverlay::new(Arc::clone(&egress) as Arc<dyn RuntimeHttpEgress>);
        let package = notion_package();
        let hire = hire("agent-1");

        overlay
            .overlay_capabilities(&hire, &package)
            .await
            .expect("first discovery succeeds");
        let first_call_count = egress.methods().len();

        tokio::time::advance(OVERLAY_CACHE_TTL + Duration::from_secs(1)).await;

        overlay
            .overlay_capabilities(&hire, &package)
            .await
            .expect("post-expiry discovery succeeds");

        assert!(
            egress.methods().len() > first_call_count,
            "an expired cache entry must trigger a fresh tools/list round trip"
        );
    }

    #[tokio::test]
    async fn overlay_cache_is_isolated_per_agent() {
        // Now that OverlayCacheKey excludes `invocation_id` (fix for the
        // cross-turn cache-defeat bug), this test is a real regression guard
        // for the `agent_id` axis specifically: both `hire()` calls would
        // collide on every OTHER key field (tenant/user/project/extension),
        // so a second discovery here can only be explained by `agent_id`
        // actually differentiating the cache key.
        let egress = Arc::new(HostedMcpDiscoveryEgress::default());
        let overlay =
            CompositionHostedMcpOverlay::new(Arc::clone(&egress) as Arc<dyn RuntimeHttpEgress>);
        let package = notion_package();

        overlay
            .overlay_capabilities(&hire("agent-1"), &package)
            .await
            .expect("agent-1 discovery succeeds");
        let after_first = egress.methods().len();
        overlay
            .overlay_capabilities(&hire("agent-2"), &package)
            .await
            .expect("agent-2 discovery succeeds");

        assert!(
            egress.methods().len() > after_first,
            "a different agent must not be served agent-1's cache entry"
        );
    }

    #[tokio::test]
    async fn overlay_maps_transient_and_permanent_discovery_errors() {
        struct FailingEgress;

        #[async_trait]
        impl RuntimeHttpEgress for FailingEgress {
            async fn execute(
                &self,
                request: RuntimeHttpEgressRequest,
            ) -> Result<RuntimeHttpEgressResponse, RuntimeHttpEgressError> {
                let _ = request.method == NetworkMethod::Post;
                Err(RuntimeHttpEgressError::Request {
                    reason: "connection_refused".to_string(),
                    request_bytes: 0,
                    response_bytes: 0,
                })
            }
        }

        let overlay = CompositionHostedMcpOverlay::new(Arc::new(FailingEgress));
        let error = overlay
            .overlay_capabilities(&hire("agent-1"), &notion_package())
            .await
            .expect_err("egress failure must surface as a discovery error");

        assert!(matches!(error, HostedMcpOverlayError::Transient(_)));
    }

    #[tokio::test]
    async fn overlay_failed_discovery_is_not_cached_and_retries() {
        struct FailOnceEgress {
            calls: std::sync::atomic::AtomicUsize,
        }

        #[async_trait]
        impl RuntimeHttpEgress for FailOnceEgress {
            async fn execute(
                &self,
                request: RuntimeHttpEgressRequest,
            ) -> Result<RuntimeHttpEgressResponse, RuntimeHttpEgressError> {
                if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    return Err(RuntimeHttpEgressError::Request {
                        reason: "connection_refused".to_string(),
                        request_bytes: 0,
                        response_bytes: 0,
                    });
                }
                HostedMcpDiscoveryEgress::default().execute(request).await
            }
        }

        let overlay = CompositionHostedMcpOverlay::new(Arc::new(FailOnceEgress {
            calls: std::sync::atomic::AtomicUsize::new(0),
        }));
        let package = notion_package();
        let hire = hire("agent-1");

        overlay
            .overlay_capabilities(&hire, &package)
            .await
            .expect_err("first call fails");
        let descriptors = overlay
            .overlay_capabilities(&hire, &package)
            .await
            .expect("second call retries instead of replaying a cached failure");

        assert_eq!(descriptors.len(), 1);
    }

    #[tokio::test]
    async fn overlay_concurrent_calls_for_same_key_single_flight_to_one_discovery() {
        let egress = Arc::new(HostedMcpDiscoveryEgress::default());
        let overlay = Arc::new(CompositionHostedMcpOverlay::new(
            Arc::clone(&egress) as Arc<dyn RuntimeHttpEgress>
        ));
        let package = Arc::new(notion_package());
        let hire = Arc::new(hire("agent-1"));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let overlay = Arc::clone(&overlay);
            let package = Arc::clone(&package);
            let hire = Arc::clone(&hire);
            handles.push(tokio::spawn(async move {
                overlay.overlay_capabilities(&hire, &package).await
            }));
        }
        let results = futures::future::join_all(handles).await;
        for result in results {
            result
                .expect("task joins")
                .expect("every concurrent call succeeds");
        }

        // One discovery: initialize + notifications/initialized + tools/list.
        assert_eq!(
            egress.methods().len(),
            3,
            "single-flight must collapse concurrent discoveries into one"
        );
        let inflight_len = {
            // Give any straggling cleanup task a chance to run.
            tokio::task::yield_now().await;
            overlay
                .inflight
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len()
        };
        assert_eq!(inflight_len, 0, "inflight map must not leak entries");
    }

    #[tokio::test]
    async fn overlay_capabilities_cleans_up_inflight_entry_when_cancelled_by_timeout() {
        // B regression: a caller-side cancellation (mirroring surface.rs's
        // OVERLAY_SURFACE_BUDGET timeout dropping the discovery future
        // mid-`.await`) must not orphan the `inflight` entry.
        struct StallingEgress;

        #[async_trait]
        impl RuntimeHttpEgress for StallingEgress {
            async fn execute(
                &self,
                _request: RuntimeHttpEgressRequest,
            ) -> Result<RuntimeHttpEgressResponse, RuntimeHttpEgressError> {
                std::future::pending::<()>().await;
                unreachable!("stalling egress never resolves");
            }
        }

        let overlay = Arc::new(CompositionHostedMcpOverlay::new(Arc::new(StallingEgress)));
        let package = notion_package();
        let hire = hire("agent-1");

        let result = tokio::time::timeout(
            Duration::from_millis(50),
            overlay.overlay_capabilities(&hire, &package),
        )
        .await;
        assert!(
            result.is_err(),
            "expected the outer timeout to cancel the stalled discovery"
        );

        assert_eq!(
            overlay
                .inflight
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            0,
            "inflight entry must not leak when the caller cancels the future"
        );
    }

    #[tokio::test]
    async fn overlay_cache_eviction_respects_max_entries() {
        let egress = Arc::new(HostedMcpDiscoveryEgress::default());
        let overlay =
            CompositionHostedMcpOverlay::new(Arc::clone(&egress) as Arc<dyn RuntimeHttpEgress>);
        let package = notion_package();

        // Force the cap by inserting synthetic entries directly.
        {
            let mut store = overlay.store.lock().await;
            for index in 0..MAX_OVERLAY_CACHE_ENTRIES {
                let key = OverlayCacheKey {
                    tenant_id: TenantId::new("acme").unwrap(),
                    user_id: UserId::new("buyer-1").unwrap(),
                    agent_id: AgentId::new(format!("synthetic-{index}")).unwrap(),
                    project_id: None,
                    extension_id: package.id.clone(),
                    manifest_digest: None,
                };
                store.insert(
                    key,
                    CacheEntry {
                        fetched_at: Instant::now() - Duration::from_secs(index as u64),
                        descriptors: Arc::new(Vec::new()),
                    },
                );
            }
            assert_eq!(store.len(), MAX_OVERLAY_CACHE_ENTRIES);
        }

        overlay
            .overlay_capabilities(&hire("agent-fresh"), &package)
            .await
            .expect("discovery succeeds even at cache capacity");

        let store = overlay.store.lock().await;
        assert!(
            store.len() <= MAX_OVERLAY_CACHE_ENTRIES,
            "cache must stay bounded at MAX_OVERLAY_CACHE_ENTRIES"
        );
        // Eviction-ordering assertion: `fetched_at = now - index` means the
        // highest index is the OLDEST synthetic entry — assert specifically
        // that one is gone, not just that *some* entry was evicted.
        let oldest_key = OverlayCacheKey {
            tenant_id: TenantId::new("acme").unwrap(),
            user_id: UserId::new("buyer-1").unwrap(),
            agent_id: AgentId::new(format!("synthetic-{}", MAX_OVERLAY_CACHE_ENTRIES - 1)).unwrap(),
            project_id: None,
            extension_id: package.id.clone(),
            manifest_digest: None,
        };
        assert!(
            !store.contains_key(&oldest_key),
            "insert() must evict the oldest entry (by fetched_at), not an arbitrary one"
        );
    }
}
