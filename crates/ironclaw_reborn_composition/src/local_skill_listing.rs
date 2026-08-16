//! Skill-listing source for the `ironclaw skills` CLI.
//!
//! Composition owns the backend choice: user skills live on the durable
//! `/tenants` mount, bundled system skills on the `/projects` disk mount.
//! Owners are discovered from the store rather than assumed, because the CLI
//! cannot know which users exist -- WebUI login mints them at runtime.

use std::{path::Path, sync::Arc};

use ironclaw_extension_host::skill_listing::{
    RebornSkillListError, list_reborn_local_skills_for_owner,
};
use ironclaw_filesystem::{
    CompositeRootFilesystem, DiskFilesystem, FileType, FilesystemError, RootFilesystem,
};
use ironclaw_host_api::{AgentId, HostPath, ResourceScope, TenantId, UserId, VirtualPath};
use ironclaw_skills::{ScopedSkillManagementPort, SkillSummary};

use crate::error::RebornBuildError;
use crate::factory::{
    mount_project_roots, mount_skill_store_for_profile, owner_scope_from_runtime_identity,
};
use crate::local_dev_mounts::scoped_skill_management_mount_view;
use crate::root::profile::RebornCompositionProfile;

/// One `(tenant, user)` skill owner backed by the durable store.
#[derive(Debug, Clone)]
pub struct SkillOwner {
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub scope: ResourceScope,
}

/// Skill-management port plus every owner the store knows about.
pub struct SkillListingSource {
    port: Arc<ScopedSkillManagementPort>,
    owners: Vec<SkillOwner>,
}

impl SkillListingSource {
    /// Skills for one owner; the port behind it stays private.
    pub async fn list_for_owner(
        &self,
        owner: &SkillOwner,
    ) -> Result<Vec<SkillSummary>, RebornSkillListError> {
        list_reborn_local_skills_for_owner(&self.port, owner.scope.clone()).await
    }

    pub fn owners(&self) -> &[SkillOwner] {
        &self.owners
    }
}

/// Open the local runtime store for skill listing.
///
/// `None` when `root` does not exist yet, so listing reports bundled skills
/// without creating state. The configured owner is always included even with an
/// empty skill root, so a fresh store still lists under its own heading.
pub async fn open_skill_listing_source(
    root: &Path,
    profile: RebornCompositionProfile,
    config_file: Option<&ironclaw_reborn_config::RebornConfigFile>,
    tenant_id: TenantId,
    agent_id: AgentId,
    owner_id: UserId,
) -> Result<Option<SkillListingSource>, RebornBuildError> {
    let exists = root
        .try_exists()
        .map_err(|error| RebornBuildError::InvalidConfig {
            reason: format!("local runtime skill storage root could not be inspected: {error}"),
        })?;
    if !exists {
        return Ok(None);
    }
    if !root.is_dir() {
        return Err(RebornBuildError::InvalidConfig {
            reason: "local runtime skill storage root is not a directory".to_string(),
        });
    }

    let mut composite = CompositeRootFilesystem::new();
    // With no database yet the configured owner is the only one.
    let durable_mounted =
        mount_skill_store_for_profile(root, profile, config_file, &mut composite).await?;
    let filesystem = add_project_roots(root, composite)?;

    let configured = SkillOwner {
        scope: owner_scope_from_runtime_identity(
            owner_id.clone(),
            tenant_id.clone(),
            agent_id.clone(),
        ),
        tenant_id,
        user_id: owner_id.clone(),
    };
    let owners = if durable_mounted {
        discover_skill_owners(filesystem.as_ref(), &agent_id, configured).await?
    } else {
        vec![configured]
    };
    Ok(Some(SkillListingSource {
        port: Arc::new(skill_port(owner_id, filesystem)),
        owners,
    }))
}

/// Mounts `/projects` only. Production mounts more, but `mount_local` requires
/// each directory to already exist, and `skills list` must not create any.
fn add_project_roots(
    root: &Path,
    mut composite: CompositeRootFilesystem,
) -> Result<Arc<dyn RootFilesystem>, RebornBuildError> {
    let mut disk = DiskFilesystem::new();
    disk.mount_local(
        VirtualPath::new("/projects").map_err(RebornBuildError::Mount)?,
        HostPath::from_path_buf(root.to_path_buf()),
    )?;
    mount_project_roots(&mut composite, Arc::new(disk))?;
    Ok(Arc::new(composite))
}

fn skill_port(owner_id: UserId, filesystem: Arc<dyn RootFilesystem>) -> ScopedSkillManagementPort {
    ScopedSkillManagementPort::new_with_mount_resolver(
        owner_id,
        filesystem,
        Arc::new(scoped_skill_management_mount_view),
    )
}

/// Test-only: stand the durable store up the way `serve` does on first boot and
/// install one user skill, so a test can seed the store listing then reads.
#[cfg(any(test, feature = "test-support"))]
pub async fn seed_skill_for_test(
    root: &Path,
    tenant_id: TenantId,
    agent_id: AgentId,
    user_id: UserId,
    name: &str,
    content: &str,
) -> Result<(), RebornBuildError> {
    let mut composite = CompositeRootFilesystem::new();
    crate::factory::open_or_create_libsql_roots(root, &mut composite).await?;
    let filesystem = add_project_roots(root, composite)?;
    let scope = owner_scope_from_runtime_identity(user_id.clone(), tenant_id, agent_id);
    skill_port(user_id, filesystem)
        .install_for_scope(scope, Some(name), content)
        .await
        .map_err(|error| RebornBuildError::InvalidConfig {
            reason: format!("seed skill '{name}' could not be installed: {error}"),
        })?;
    Ok(())
}

/// Walk `/tenants/*/users/*/skills` for owners with a non-empty skill root.
/// `configured` is listed first and never duplicated.
async fn discover_skill_owners(
    filesystem: &dyn RootFilesystem,
    agent_id: &AgentId,
    configured: SkillOwner,
) -> Result<Vec<SkillOwner>, RebornBuildError> {
    let mut owners = vec![configured];
    for tenant in child_directories(filesystem, "/tenants").await? {
        let Ok(tenant_id) = TenantId::new(tenant.clone()) else {
            tracing::warn!(
                tenant = %tenant,
                "Skipping stored skill owner whose tenant directory is not a valid tenant id"
            );
            continue;
        };
        let users_root = format!("/tenants/{tenant}/users");
        for user in child_directories(filesystem, &users_root).await? {
            let Ok(user_id) = UserId::new(user.clone()) else {
                tracing::warn!(
                    tenant = %tenant,
                    user = %user,
                    "Skipping stored skill owner whose user directory is not a valid user id"
                );
                continue;
            };
            let already_listed = owners.iter().any(|owner| {
                owner.tenant_id == tenant_id && owner.user_id.as_str() == user_id.as_str()
            });
            if already_listed {
                continue;
            }
            let skills_root = format!("{users_root}/{user}/skills");
            if child_directories(filesystem, &skills_root)
                .await?
                .is_empty()
            {
                continue;
            }
            owners.push(SkillOwner {
                scope: owner_scope_from_runtime_identity(
                    user_id.clone(),
                    tenant_id.clone(),
                    agent_id.clone(),
                ),
                tenant_id: tenant_id.clone(),
                user_id,
            });
        }
    }
    Ok(owners)
}

/// Direct child directories. An absent path lists as empty; every other error
/// propagates, so a wrong mount set cannot read as "no owners".
async fn child_directories(
    filesystem: &dyn RootFilesystem,
    path: &str,
) -> Result<Vec<String>, RebornBuildError> {
    let path = VirtualPath::new(path.to_string()).map_err(RebornBuildError::Mount)?;
    match filesystem.list_dir(&path).await {
        Ok(entries) => Ok(entries
            .into_iter()
            .filter(|entry| entry.file_type == FileType::Directory)
            .map(|entry| entry.name)
            .collect()),
        // silent-ok: an owner root never written is empty, not a failure.
        Err(FilesystemError::NotFound { .. }) => Ok(Vec::new()),
        Err(error) => Err(RebornBuildError::Filesystem(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Parsed, not named: the deployment-mode ratchet bans a profile variant in
    // any non-`tests.rs` file, and this module keeps its tests inline.
    fn test_profile() -> RebornCompositionProfile {
        "local-dev".parse().expect("local-dev profile")
    }

    fn identity() -> (TenantId, AgentId, UserId) {
        (
            TenantId::new("reborn-cli").expect("tenant"),
            AgentId::new("reborn-cli-agent").expect("agent"),
            UserId::new("reborn-cli").expect("owner"),
        )
    }

    #[tokio::test]
    async fn missing_storage_root_reports_no_source_without_creating_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("missing-local-dev");
        let (tenant_id, agent_id, owner_id) = identity();

        let source =
            open_skill_listing_source(&root, test_profile(), None, tenant_id, agent_id, owner_id)
                .await
                .expect("listing source");

        assert!(source.is_none());
        assert!(!root.exists());
    }

    #[tokio::test]
    async fn non_directory_storage_root_fails_loudly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("local-dev");
        std::fs::write(&root, "not a directory").expect("storage root file");
        let (tenant_id, agent_id, owner_id) = identity();

        let error = match open_skill_listing_source(
            &root,
            test_profile(),
            None,
            tenant_id,
            agent_id,
            owner_id,
        )
        .await
        {
            Ok(_) => panic!("file storage root must fail"),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("not a directory"),
            "unexpected error: {error}"
        );
    }

    /// hosted-single-tenant is Postgres-backed: no fallback to the local file.
    #[tokio::test]
    async fn hosted_single_tenant_does_not_fall_back_to_the_local_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("hosted-single-tenant");
        std::fs::create_dir_all(&root).expect("storage root");
        let (tenant_id, agent_id, owner_id) = identity();
        let hosted: RebornCompositionProfile =
            "hosted-single-tenant".parse().expect("hosted profile");

        let error =
            match open_skill_listing_source(&root, hosted, None, tenant_id, agent_id, owner_id)
                .await
            {
                Ok(_) => panic!("hosted single-tenant must resolve Postgres storage"),
                Err(error) => error,
            };

        assert!(
            error.to_string().contains("postgres"),
            "unexpected error: {error}"
        );
        assert!(
            !crate::factory::local_dev_db_path(&root).exists(),
            "hosted single-tenant must not create the local libSQL store"
        );
    }

    /// A storage root with no database lists the configured owner only.
    #[tokio::test]
    async fn listing_does_not_create_the_durable_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("local-dev");
        std::fs::create_dir_all(&root).expect("storage root");
        let (tenant_id, agent_id, owner_id) = identity();

        let source =
            open_skill_listing_source(&root, test_profile(), None, tenant_id, agent_id, owner_id)
                .await
                .expect("listing source")
                .expect("source for existing root");

        assert_eq!(source.owners().len(), 1);
        assert_eq!(source.owners()[0].user_id.as_str(), "reborn-cli");
        assert!(
            !crate::factory::local_dev_db_path(&root).exists(),
            "listing must not create the durable store"
        );
    }

    /// The CLI cannot know a WebUI-minted user id, so a skill root written under
    /// an unrelated tenant/user must still surface. The configured owner is
    /// listed even with no skills of its own.
    #[tokio::test]
    async fn discovers_owners_the_cli_was_never_told_about() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("local-dev");
        std::fs::create_dir_all(&root).expect("storage root");
        let (tenant_id, agent_id, owner_id) = identity();

        seed_skill_for_test(
            &root,
            TenantId::new("hosted-tenant").expect("tenant"),
            agent_id.clone(),
            UserId::new("alice@corp.example").expect("user"),
            "deploy-notes",
            "---\nname: deploy-notes\ndescription: dynamic user skill\n---\nUse it.\n",
        )
        .await
        .expect("install skill for dynamically created user");

        let source =
            open_skill_listing_source(&root, test_profile(), None, tenant_id, agent_id, owner_id)
                .await
                .expect("listing source")
                .expect("source for existing root");

        let owners = source.owners();
        assert_eq!(owners[0].user_id.as_str(), "reborn-cli");
        assert!(
            owners.iter().any(|owner| {
                owner.tenant_id.as_str() == "hosted-tenant"
                    && owner.user_id.as_str() == "alice@corp.example"
            }),
            "dynamically created owner must be discovered: {:?}",
            owners
                .iter()
                .map(|owner| (owner.tenant_id.as_str(), owner.user_id.as_str()))
                .collect::<Vec<_>>()
        );
    }
}
