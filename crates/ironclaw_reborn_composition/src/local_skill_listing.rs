//! Skill-listing source for the `ironclaw skills` CLI.
//!
//! Composition owns the backend choice: user skills live on the durable
//! `/tenants` mount, bundled system skills on the `/projects` disk mount.
//! Owners are discovered from the store rather than assumed, because the CLI
//! cannot know which users exist -- WebUI login mints them at runtime.

use std::{path::Path, sync::Arc};

use ironclaw_filesystem::{
    CompositeRootFilesystem, DiskFilesystem, FileType, FilesystemError, RootFilesystem,
};
use ironclaw_host_api::{AgentId, HostPath, ResourceScope, TenantId, UserId, VirtualPath};
use ironclaw_skills::ScopedSkillManagementPort;

use crate::error::RebornBuildError;
use crate::factory::{
    build_default_local_dev_database_roots, mount_local_dev_project_roots,
    owner_scope_from_runtime_identity,
};
use crate::local_dev_mounts::scoped_skill_management_mount_view;

/// One `(tenant, user)` skill owner backed by the durable store.
#[derive(Debug, Clone)]
pub struct LocalSkillOwner {
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub scope: ResourceScope,
}

/// Skill-management port plus every owner the store knows about.
pub struct LocalSkillListingSource {
    port: Arc<ScopedSkillManagementPort>,
    owners: Vec<LocalSkillOwner>,
}

impl LocalSkillListingSource {
    pub fn port(&self) -> &ScopedSkillManagementPort {
        &self.port
    }

    pub fn owners(&self) -> &[LocalSkillOwner] {
        &self.owners
    }
}

/// Open the local runtime store for skill listing.
///
/// `None` when `root` does not exist yet, so listing reports bundled skills
/// without creating state. The configured owner is always included even with an
/// empty skill root, so a fresh store still lists under its own heading.
pub async fn open_local_skill_listing_source(
    root: &Path,
    tenant_id: TenantId,
    agent_id: AgentId,
    owner_id: UserId,
) -> Result<Option<LocalSkillListingSource>, RebornBuildError> {
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
    build_default_local_dev_database_roots(root, &mut composite).await?;
    // Only `/projects` is mounted, rooted at the storage root: `mount_local`
    // requires the host directory to exist, and listing must not create skill
    // dirs. Bundled system skills resolve through `/projects/system/skills` and
    // list as empty when that directory has not been written yet. Opening the
    // database does create `reborn-local-dev.db` under an existing root -- the
    // same file `serve` opens, never a second store.
    let mut disk = DiskFilesystem::new();
    disk.mount_local(
        VirtualPath::new("/projects").map_err(RebornBuildError::Mount)?,
        HostPath::from_path_buf(root.to_path_buf()),
    )?;
    mount_local_dev_project_roots(&mut composite, Arc::new(disk))?;
    let filesystem: Arc<dyn RootFilesystem> = Arc::new(composite);

    let configured = LocalSkillOwner {
        scope: owner_scope_from_runtime_identity(
            owner_id.clone(),
            tenant_id.clone(),
            agent_id.clone(),
        ),
        tenant_id,
        user_id: owner_id.clone(),
    };
    let owners = discover_skill_owners(filesystem.as_ref(), &agent_id, configured).await?;
    let port = ScopedSkillManagementPort::new_with_mount_resolver(
        owner_id,
        filesystem,
        Arc::new(scoped_skill_management_mount_view),
    );
    Ok(Some(LocalSkillListingSource {
        port: Arc::new(port),
        owners,
    }))
}

/// Walk `/tenants/*/users/*/skills` for owners with a non-empty skill root.
/// `configured` is listed first and never duplicated.
async fn discover_skill_owners(
    filesystem: &dyn RootFilesystem,
    agent_id: &AgentId,
    configured: LocalSkillOwner,
) -> Result<Vec<LocalSkillOwner>, RebornBuildError> {
    let mut owners = vec![configured];
    for tenant in child_directories(filesystem, "/tenants").await? {
        let Ok(tenant_id) = TenantId::new(tenant.clone()) else {
            continue;
        };
        let users_root = format!("/tenants/{tenant}/users");
        for user in child_directories(filesystem, &users_root).await? {
            let Ok(user_id) = UserId::new(user.clone()) else {
                continue;
            };
            let already_listed = owners.iter().any(|owner| {
                owner.tenant_id == tenant_id && owner.user_id.as_str() == user_id.as_str()
            });
            if already_listed {
                continue;
            }
            let skills_root = format!("{users_root}/{user}/skills");
            if child_directories(filesystem, &skills_root).await?.is_empty() {
                continue;
            }
            owners.push(LocalSkillOwner {
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

/// Direct child directories of `path`; an absent path lists as empty.
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
        Err(FilesystemError::NotFound { .. }) => Ok(Vec::new()),
        Err(FilesystemError::MountNotFound { .. }) => Ok(Vec::new()),
        Err(error) => Err(RebornBuildError::Filesystem(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let source = open_local_skill_listing_source(&root, tenant_id, agent_id, owner_id)
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

        let error = match open_local_skill_listing_source(&root, tenant_id, agent_id, owner_id)
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

    /// The CLI cannot know a WebUI-minted user id, so a skill root written under
    /// an unrelated tenant/user must still surface. The configured owner is
    /// listed even with no skills of its own.
    #[tokio::test]
    async fn discovers_owners_the_cli_was_never_told_about() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("local-dev");
        std::fs::create_dir_all(&root).expect("storage root");
        let (tenant_id, agent_id, owner_id) = identity();

        let seeded = open_local_skill_listing_source(
            &root,
            tenant_id.clone(),
            agent_id.clone(),
            owner_id.clone(),
        )
        .await
        .expect("listing source")
        .expect("source for existing root");
        let dynamic_scope = owner_scope_from_runtime_identity(
            UserId::new("alice@corp.example").expect("user"),
            TenantId::new("hosted-tenant").expect("tenant"),
            agent_id.clone(),
        );
        seeded
            .port()
            .install_for_scope(
                dynamic_scope,
                Some("deploy-notes"),
                "---\nname: deploy-notes\ndescription: dynamic user skill\n---\nUse it.\n",
            )
            .await
            .expect("install skill for dynamically created user");
        drop(seeded);

        let source = open_local_skill_listing_source(&root, tenant_id, agent_id, owner_id)
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
