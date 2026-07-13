use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
};

use ironclaw_host_api::{
    CapabilityDescriptor, CapabilityId, CapabilityProfileSchemaRef, ExtensionId,
};
use parking_lot::RwLock;

use crate::{CapabilityManifest, CapabilityVisibility, ExtensionError, ExtensionPackage};

/// Registry of validated extension packages and declared capabilities.
#[derive(Debug, Default, Clone)]
pub struct ExtensionRegistry {
    packages: HashMap<ExtensionId, ExtensionPackage>,
    capabilities: HashMap<CapabilityId, CapabilityDescriptor>,
    capability_visibility: HashMap<CapabilityId, CapabilityVisibility>,
    extension_order: Vec<ExtensionId>,
    capability_order: Vec<CapabilityId>,
}

impl ExtensionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, package: ExtensionPackage) -> Result<(), ExtensionError> {
        self.validate_insertable(&package)?;
        self.insert_validated(package);
        Ok(())
    }

    pub(crate) fn validate_insertable(
        &self,
        package: &ExtensionPackage,
    ) -> Result<(), ExtensionError> {
        validate_package_consistency(package)?;

        if self.packages.contains_key(&package.id) {
            return Err(ExtensionError::DuplicateExtension {
                id: package.id.clone(),
            });
        }

        self.validate_capabilities_available(package, None)
    }

    pub(crate) fn validate_replacement(
        &self,
        package: &ExtensionPackage,
    ) -> Result<(), ExtensionError> {
        validate_package_consistency(package)?;
        self.existing_package(&package.id)?;
        self.validate_capabilities_available(package, Some(&package.id))
    }

    fn validate_capabilities_available(
        &self,
        package: &ExtensionPackage,
        replacing: Option<&ExtensionId>,
    ) -> Result<(), ExtensionError> {
        let mut seen_capabilities = HashSet::new();
        for descriptor in &package.capabilities {
            let capability_belongs_to_replaced_package = replacing
                .and_then(|id| self.packages.get(id))
                .map(|current| {
                    current
                        .capabilities
                        .iter()
                        .any(|current| current.id == descriptor.id)
                })
                .unwrap_or(false);
            if !seen_capabilities.insert(descriptor.id.clone())
                || (self.capabilities.contains_key(&descriptor.id)
                    && !capability_belongs_to_replaced_package)
            {
                return Err(ExtensionError::DuplicateCapability {
                    id: descriptor.id.clone(),
                });
            }
            if descriptor.provider != package.id {
                return Err(ExtensionError::InvalidManifest {
                    reason: format!(
                        "descriptor {} provider {} does not match package {}",
                        descriptor.id, descriptor.provider, package.id
                    ),
                });
            }
        }

        Ok(())
    }

    pub(crate) fn existing_package(
        &self,
        id: &ExtensionId,
    ) -> Result<&ExtensionPackage, ExtensionError> {
        self.packages
            .get(id)
            .ok_or_else(|| ExtensionError::ExtensionNotFound { id: id.clone() })
    }

    pub(crate) fn insert_validated(&mut self, package: ExtensionPackage) {
        for descriptor in &package.capabilities {
            self.capability_order.push(descriptor.id.clone());
            self.capabilities
                .insert(descriptor.id.clone(), descriptor.clone());
            if let Some(capability) = package
                .manifest
                .capabilities
                .iter()
                .find(|capability| capability.id == descriptor.id)
            {
                self.capability_visibility
                    .insert(descriptor.id.clone(), capability.visibility);
            }
        }
        self.extension_order.push(package.id.clone());
        self.packages.insert(package.id.clone(), package);
    }

    pub(crate) fn replace_validated(&mut self, package: ExtensionPackage) {
        let id = package.id.clone();
        let extension_index = self
            .extension_order
            .iter()
            .position(|extension_id| extension_id == &id);
        let Some(current) = self.packages.get(&id).cloned() else {
            debug_assert!(
                false,
                "replace_validated called without an existing package"
            );
            return;
        };
        let current_capability_ids = current
            .capabilities
            .iter()
            .map(|descriptor| descriptor.id.clone())
            .collect::<HashSet<_>>();
        let capability_insert_index = self
            .capability_order
            .iter()
            .position(|capability_id| current_capability_ids.contains(capability_id))
            .unwrap_or(self.capability_order.len());

        for capability_id in &current_capability_ids {
            self.capabilities.remove(capability_id);
            self.capability_visibility.remove(capability_id);
        }
        self.capability_order
            .retain(|capability_id| !current_capability_ids.contains(capability_id));
        for (offset, descriptor) in package.capabilities.iter().enumerate() {
            self.capability_order
                .insert(capability_insert_index + offset, descriptor.id.clone());
            self.capabilities
                .insert(descriptor.id.clone(), descriptor.clone());
            if let Some(capability) = package
                .manifest
                .capabilities
                .iter()
                .find(|capability| capability.id == descriptor.id)
            {
                self.capability_visibility
                    .insert(descriptor.id.clone(), capability.visibility);
            }
        }
        if let Some(index) = extension_index {
            self.extension_order[index] = id.clone();
        } else {
            debug_assert!(
                false,
                "replace_validated found package missing from extension_order"
            );
            self.extension_order.push(id.clone());
        }
        self.packages.insert(id, package);
    }

    pub fn update(&mut self, package: ExtensionPackage) -> Result<(), ExtensionError> {
        self.validate_replacement(&package)?;
        self.replace_validated(package);
        Ok(())
    }

    pub fn remove(&mut self, id: &ExtensionId) -> Option<ExtensionPackage> {
        let package = self.packages.remove(id)?;
        self.extension_order
            .retain(|extension_id| extension_id != id);
        for descriptor in &package.capabilities {
            self.capabilities.remove(&descriptor.id);
            self.capability_visibility.remove(&descriptor.id);
            self.capability_order
                .retain(|capability_id| capability_id != &descriptor.id);
        }
        Some(package)
    }

    pub fn get_extension(&self, id: &ExtensionId) -> Option<&ExtensionPackage> {
        self.packages.get(id)
    }

    pub fn get_capability(&self, id: &CapabilityId) -> Option<&CapabilityDescriptor> {
        self.capabilities.get(id)
    }

    pub fn capability_visibility(&self, id: &CapabilityId) -> Option<CapabilityVisibility> {
        self.capability_visibility.get(id).copied()
    }

    pub fn extensions(&self) -> impl Iterator<Item = &ExtensionPackage> {
        self.extension_order
            .iter()
            .filter_map(|id| self.packages.get(id))
    }

    pub fn capabilities(&self) -> impl Iterator<Item = &CapabilityDescriptor> {
        self.capability_order
            .iter()
            .filter_map(|id| self.capabilities.get(id))
    }

    /// Returns a NEW registry with `descriptor` merged into a clone of its
    /// provider's package. Never mutates `self` or the registry `self` was
    /// snapshotted from — callers own a throwaway, per-request clone. Used
    /// by `ironclaw_host_runtime`'s per-request registry resolution to make
    /// a per-user discovered hosted-MCP capability resolvable at
    /// invoke/resume time without ever writing it into the shared boot
    /// registry (the hosted-MCP overlay's own invariant: discovered
    /// descriptors are never written into the shared `ExtensionRegistry`).
    ///
    /// Mirrors `package_with_discovered_hosted_mcp_tools`'s boot-time shape
    /// — the provider's other declared capabilities are replaced, not
    /// appended, because a hosted-MCP provider's static manifest capability
    /// is a schema template, never meant to be directly invocable once real
    /// discovery resolves a capability (see that function's own regression
    /// test). Unlike that helper, the manifest capability entry is built
    /// FROM `descriptor` field-for-field instead of recomputing
    /// effects/permission from raw MCP tool annotations — this guarantees
    /// the merged registry's resolved descriptor is identical, in every
    /// trust/authorization-relevant field, to the `descriptor` the caller
    /// passed in, so an ambient grant minted against that same discovered
    /// descriptor always effects-matches.
    ///
    /// Fails if `descriptor.provider` is not a known package in this
    /// registry, or if the merged package fails consistency validation
    /// (e.g. the registry's snapshot of the provider's manifest changed
    /// between discovery and merge). Callers should treat `Err` as
    /// fail-safe: leave the base registry unchanged rather than propagate.
    // TODO(M1 follow-up, review item 5): this REPLACES the provider's
    // capability list (`manifest.capabilities = vec![manifest_capability]`
    // below), it does not append. The idempotency guard above only catches
    // re-merging the SAME id; merging two DISTINCT discovered ids into the
    // same provider sequentially would silently drop the first one's
    // resolvability. Safe today because every call site resolves exactly
    // one target id per request (`resolve_invocation_registry` merges the
    // one id the caller is invoking/resuming). If a future caller ever
    // needs to merge multiple discovered ids from the same provider into
    // one registry snapshot, this needs to accumulate onto the EXISTING
    // merged capabilities/manifest entries instead of replacing them.
    pub fn merge_discovered_capability(
        &self,
        descriptor: CapabilityDescriptor,
    ) -> Result<ExtensionRegistry, ExtensionError> {
        let package = self.existing_package(&descriptor.provider)?;
        if package
            .capabilities
            .iter()
            .any(|existing| existing.id == descriptor.id)
        {
            // Already present (e.g. a second discovery within the same
            // request) — nothing to merge.
            return Ok(self.clone());
        }
        let manifest_capability = discovered_capability_manifest_entry(package, &descriptor)?;
        let mut manifest = package.manifest.clone();
        manifest.capabilities = vec![manifest_capability];
        let merged_package =
            ExtensionPackage::from_host_bundled_manifest_with_inline_dynamic_schemas(
                manifest,
                package.root.clone(),
                package.manifest_digest(),
                vec![descriptor],
            )?;
        let mut updated = self.clone();
        updated.update(merged_package)?;
        Ok(updated)
    }
}

fn discovered_capability_manifest_entry(
    package: &ExtensionPackage,
    descriptor: &CapabilityDescriptor,
) -> Result<CapabilityManifest, ExtensionError> {
    let provider_prefix = format!("{}.", package.id.as_str());
    let tool_name = descriptor
        .id
        .as_str()
        .strip_prefix(&provider_prefix)
        .unwrap_or(descriptor.id.as_str());
    let schema_path = tool_name.replace('.', "/");
    let input_schema_ref = CapabilityProfileSchemaRef::new(format!(
        "schemas/{}/dynamic/{schema_path}.input.v1.json",
        package.id.as_str()
    ))
    .map_err(|error| ExtensionError::InvalidManifest {
        reason: format!("invalid discovered MCP input schema ref: {error}"),
    })?;
    let output_schema_ref = CapabilityProfileSchemaRef::new(format!(
        "schemas/{}/dynamic/{schema_path}.output.v1.json",
        package.id.as_str()
    ))
    .map_err(|error| ExtensionError::InvalidManifest {
        reason: format!("invalid discovered MCP output schema ref: {error}"),
    })?;
    let required_host_ports = package
        .manifest
        .capabilities
        .first()
        .map(|capability| capability.required_host_ports.clone())
        .unwrap_or_default();
    Ok(CapabilityManifest {
        id: descriptor.id.clone(),
        implements: Vec::new(),
        description: descriptor.description.clone(),
        effects: descriptor.effects.clone(),
        default_permission: descriptor.default_permission,
        visibility: CapabilityVisibility::Model,
        input_schema_ref,
        output_schema_ref,
        prompt_doc_ref: None,
        required_host_ports,
        runtime_credentials: descriptor.runtime_credentials.clone(),
        resource_profile: descriptor.resource_profile.clone(),
    })
}

#[derive(Debug, Clone)]
pub struct SharedExtensionRegistry {
    inner: Arc<RwLock<Arc<ExtensionRegistry>>>,
    version: Arc<AtomicU64>,
}

impl SharedExtensionRegistry {
    pub fn new(registry: ExtensionRegistry) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Arc::new(registry))),
            version: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn snapshot(&self) -> Arc<ExtensionRegistry> {
        Arc::clone(&self.inner.read())
    }

    pub fn snapshot_owned(&self) -> ExtensionRegistry {
        self.snapshot().as_ref().clone()
    }

    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    pub fn insert(&self, package: ExtensionPackage) -> Result<(), ExtensionError> {
        self.with_mut_result(|registry| registry.insert(package))
    }

    pub fn update(&self, package: ExtensionPackage) -> Result<(), ExtensionError> {
        self.with_mut_result(|registry| registry.update(package))
    }

    pub fn upsert(&self, package: ExtensionPackage) -> Result<(), ExtensionError> {
        self.with_mut_result(|registry| {
            if registry.get_extension(&package.id).is_some() {
                registry.update(package)
            } else {
                registry.insert(package)
            }
        })
    }

    pub fn remove(&self, id: &ExtensionId) -> Option<ExtensionPackage> {
        let mut guard = self.inner.write();
        let removed = Arc::make_mut(&mut guard).remove(id);
        if removed.is_some() {
            self.version.fetch_add(1, Ordering::AcqRel);
        }
        removed
    }

    fn with_mut_result<R>(
        &self,
        f: impl FnOnce(&mut ExtensionRegistry) -> Result<R, ExtensionError>,
    ) -> Result<R, ExtensionError> {
        let mut guard = self.inner.write();
        let result = f(Arc::make_mut(&mut guard))?;
        self.version.fetch_add(1, Ordering::AcqRel);
        Ok(result)
    }

    pub fn replace(&self, registry: ExtensionRegistry) {
        let mut guard = self.inner.write();
        *guard = Arc::new(registry);
        self.version.fetch_add(1, Ordering::AcqRel);
    }
}

impl Default for SharedExtensionRegistry {
    fn default() -> Self {
        Self::new(ExtensionRegistry::default())
    }
}

pub(crate) fn validate_package_consistency(
    package: &ExtensionPackage,
) -> Result<(), ExtensionError> {
    package.validate_consistency()
}

#[cfg(test)]
mod tests {
    use std::thread;

    use ironclaw_host_api::{HostPortCatalog, VirtualPath};

    use super::*;
    use crate::{ExtensionManifest, ManifestSource};

    #[test]
    fn shared_registry_upsert_inserts_new_and_updates_existing() {
        let registry = SharedExtensionRegistry::default();
        let initial = test_package("fixture", &["search"]);
        registry.upsert(initial).expect("insert through upsert");

        let updated = test_package("fixture", &["write"]);
        registry.upsert(updated).expect("update through upsert");
        let snapshot = registry.snapshot();

        assert!(snapshot.get_extension(&extension_id("fixture")).is_some());
        assert!(
            snapshot
                .get_capability(&capability_id("fixture.search"))
                .is_none()
        );
        assert!(
            snapshot
                .get_capability(&capability_id("fixture.write"))
                .is_some()
        );
    }

    #[test]
    fn shared_registry_methods_cover_mutation_and_snapshot_paths() {
        let registry = SharedExtensionRegistry::default();
        registry
            .insert(test_package("alpha", &["read"]))
            .expect("insert package");
        registry
            .update(test_package("alpha", &["write"]))
            .expect("update package");
        assert!(
            registry
                .snapshot()
                .get_capability(&capability_id("alpha.write"))
                .is_some()
        );

        let held_snapshot = registry.snapshot();
        registry
            .upsert(test_package("beta", &["read"]))
            .expect("copy-on-write insert while snapshot is held");
        assert!(held_snapshot.get_extension(&extension_id("beta")).is_none());
        assert!(
            registry
                .snapshot()
                .get_extension(&extension_id("beta"))
                .is_some()
        );

        let owned = registry.snapshot_owned();
        assert!(owned.get_extension(&extension_id("alpha")).is_some());

        let removed = registry
            .remove(&extension_id("alpha"))
            .expect("remove package");
        assert_eq!(removed.id, extension_id("alpha"));
        assert!(
            registry
                .snapshot()
                .get_extension(&extension_id("alpha"))
                .is_none()
        );

        let mut replacement = ExtensionRegistry::new();
        replacement
            .insert(test_package("gamma", &["read"]))
            .expect("replacement insert");
        registry.replace(replacement);
        assert!(
            registry
                .snapshot()
                .get_extension(&extension_id("gamma"))
                .is_some()
        );
        assert!(
            registry
                .snapshot()
                .get_extension(&extension_id("beta"))
                .is_none()
        );
    }

    #[test]
    fn shared_registry_version_changes_only_on_applied_mutations() {
        let registry = SharedExtensionRegistry::default();
        let initial_version = registry.version();

        assert!(registry.remove(&extension_id("missing")).is_none());
        assert_eq!(registry.version(), initial_version);

        registry
            .insert(test_package("alpha", &["read"]))
            .expect("insert package");
        let inserted_version = registry.version();
        assert!(inserted_version > initial_version);

        let duplicate = registry
            .insert(test_package("alpha", &["write"]))
            .expect_err("duplicate extension is rejected");
        assert!(matches!(
            duplicate,
            ExtensionError::DuplicateExtension { .. }
        ));
        assert_eq!(registry.version(), inserted_version);
    }

    #[test]
    fn shared_registry_concurrent_insert_and_snapshot() {
        let registry = SharedExtensionRegistry::default();
        let writer_registry = registry.clone();
        let writer = thread::spawn(move || {
            for id in ["alpha", "beta", "gamma"] {
                writer_registry
                    .upsert(test_package(id, &["read"]))
                    .expect("writer upsert");
            }
        });

        let reader_registry = registry.clone();
        let reader = thread::spawn(move || {
            for _ in 0..16 {
                let _ = reader_registry.snapshot();
            }
        });

        writer.join().expect("writer thread");
        reader.join().expect("reader thread");

        let snapshot = registry.snapshot();
        for id in ["alpha", "beta", "gamma"] {
            assert!(snapshot.get_extension(&extension_id(id)).is_some());
        }
    }

    fn discovered_descriptor(provider: &ExtensionPackage, tool_name: &str) -> CapabilityDescriptor {
        CapabilityDescriptor {
            id: capability_id(&format!("{}.{tool_name}", provider.id.as_str())),
            provider: provider.id.clone(),
            runtime: provider.manifest.runtime_kind(),
            trust_ceiling: provider.manifest.descriptor_trust_default,
            description: format!("discovered {tool_name}"),
            parameters_schema: serde_json::json!({"type": "object"}),
            effects: vec![ironclaw_host_api::EffectKind::Network],
            default_permission: ironclaw_host_api::PermissionMode::Ask,
            runtime_credentials: Vec::new(),
            resource_profile: None,
        }
    }

    #[test]
    fn merge_discovered_capability_makes_it_resolvable_without_mutating_the_base_registry() {
        let mut base = ExtensionRegistry::new();
        let provider = test_package("notion", &["template"]);
        base.insert(provider.clone()).expect("insert provider");

        let discovered = discovered_descriptor(&provider, "notion-search");
        let merged = base
            .merge_discovered_capability(discovered.clone())
            .expect("merge succeeds");

        assert!(merged.get_capability(&discovered.id).is_some());
        assert_eq!(merged.get_capability(&discovered.id), Some(&discovered));
        // The base registry (and its provider package) is untouched — this
        // is a per-request clone, never a mutation of the snapshot it came
        // from.
        assert!(base.get_capability(&discovered.id).is_none());
        assert!(
            base.get_extension(&provider.id)
                .expect("provider still present")
                .capabilities
                .iter()
                .any(|capability| capability.id.as_str() == "notion.template")
        );
    }

    #[test]
    fn merge_discovered_capability_is_idempotent_when_already_present() {
        let mut base = ExtensionRegistry::new();
        let provider = test_package("notion", &["template"]);
        base.insert(provider.clone()).expect("insert provider");
        let discovered = discovered_descriptor(&provider, "notion-search");
        let merged_once = base
            .merge_discovered_capability(discovered.clone())
            .expect("first merge succeeds");

        let merged_twice = merged_once
            .merge_discovered_capability(discovered.clone())
            .expect("second merge is a no-op, not an error");

        assert_eq!(
            merged_twice.get_capability(&discovered.id),
            merged_once.get_capability(&discovered.id)
        );
    }

    #[test]
    fn merge_discovered_capability_fails_closed_for_unknown_provider() {
        let base = ExtensionRegistry::new();
        let orphan_provider = test_package("ghost", &["template"]);
        let discovered = discovered_descriptor(&orphan_provider, "ghost-search");

        let error = base
            .merge_discovered_capability(discovered)
            .expect_err("unknown provider must fail, not silently succeed");

        assert!(matches!(error, ExtensionError::ExtensionNotFound { .. }));
    }

    fn test_package(extension_id: &str, capabilities: &[&str]) -> ExtensionPackage {
        let capability_blocks = capabilities
            .iter()
            .map(|name| {
                format!(
                    r#"
[[capabilities]]
id = "{extension_id}.{name}"
description = "{name}"
effects = ["network"]
default_permission = "ask"
visibility = "model"
input_schema_ref = "schemas/{name}.input.json"
output_schema_ref = "schemas/{name}.output.json"
"#
                )
            })
            .collect::<String>();
        let manifest = format!(
            r#"
schema_version = "reborn.extension_manifest.v2"
id = "{extension_id}"
name = "{extension_id}"
version = "0.1.0"
description = "test extension"
trust = "third_party"

[runtime]
kind = "wasm"
module = "wasm/{extension_id}.wasm"
{capability_blocks}
"#
        );
        let manifest = ExtensionManifest::parse(
            &manifest,
            ManifestSource::HostBundled,
            &HostPortCatalog::empty(),
        )
        .expect("manifest parses");
        ExtensionPackage::from_manifest(
            manifest,
            VirtualPath::new(format!("/system/extensions/{extension_id}")).expect("root"),
        )
        .expect("package builds")
    }

    fn extension_id(value: &str) -> ExtensionId {
        ExtensionId::new(value.to_string()).expect("extension id")
    }

    fn capability_id(value: &str) -> CapabilityId {
        CapabilityId::new(value.to_string()).expect("capability id")
    }
}
