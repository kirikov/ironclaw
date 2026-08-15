use std::collections::HashSet;

use ironclaw_host_api::ResourceScope;
use ironclaw_skills::{
    ManagedSkillSource, ScopedSkillManagementError, ScopedSkillManagementPort,
    SkillManagementError, SkillManagementErrorKind,
};

use crate::RebornBuildError;
use crate::bundled_skills::bundled_reborn_skill_summaries;

/// Skills stored for one `(tenant, user)` owner.
///
/// System skills that a bundled skill already covers are dropped: the embedded
/// summary is authoritative and [`list_reborn_bundled_skills`] lists it once for
/// the whole deployment rather than repeating it per owner.
pub async fn list_reborn_local_skills_for_owner(
    skill_management: &ScopedSkillManagementPort,
    scope: ResourceScope,
) -> Result<Vec<ironclaw_skills::SkillSummary>, RebornSkillListError> {
    let mut skills = skill_management
        .list_for_scope(scope)
        .await
        .map_err(map_local_skill_management_error)?;
    let bundled_names = bundled_reborn_skill_summaries()?
        .into_iter()
        .map(|skill| skill.name)
        .collect::<HashSet<_>>();
    skills.retain(|skill| {
        !(skill.source == ManagedSkillSource::System && bundled_names.contains(&skill.name))
    });
    sort_skills(&mut skills);
    Ok(skills)
}

/// The system skills compiled into the binary. Global, not owner-scoped.
pub fn list_reborn_bundled_skills()
-> Result<Vec<ironclaw_skills::SkillSummary>, RebornSkillListError> {
    let mut skills = bundled_reborn_skill_summaries()?;
    sort_skills(&mut skills);
    Ok(skills)
}

fn sort_skills(skills: &mut [ironclaw_skills::SkillSummary]) {
    skills.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.source.as_str().cmp(right.source.as_str()))
    });
}

#[derive(Debug, thiserror::Error)]
pub enum RebornSkillListError {
    #[error(transparent)]
    Build(#[from] RebornBuildError),
    #[error("skill list request rejected: {reason}")]
    InvalidRequest { reason: String },
    #[error("skill list access denied")]
    AccessDenied,
    #[error("skill list unavailable: {reason}")]
    Unavailable { reason: String },
}

fn map_local_skill_management_error(error: ScopedSkillManagementError) -> RebornSkillListError {
    match error {
        ScopedSkillManagementError::InvalidContext { reason } => {
            RebornSkillListError::InvalidRequest { reason }
        }
        ScopedSkillManagementError::Skill(error) => map_skill_management_error(error),
    }
}

fn map_skill_management_error(error: SkillManagementError) -> RebornSkillListError {
    match error.kind() {
        SkillManagementErrorKind::InvalidInput
        | SkillManagementErrorKind::NotFound
        | SkillManagementErrorKind::Conflict
        | SkillManagementErrorKind::InvalidSkill => RebornSkillListError::InvalidRequest {
            reason: error
                .reason()
                .unwrap_or("skill management request rejected")
                .to_string(),
        },
        SkillManagementErrorKind::FilesystemDenied => RebornSkillListError::AccessDenied,
        SkillManagementErrorKind::Resource => RebornSkillListError::Unavailable {
            reason: "skill management resource unavailable".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use ironclaw_filesystem::DiskFilesystem;
    use ironclaw_host_api::{
        HostPath, InvocationId, MountAlias, MountGrant, MountPermissions, MountView, UserId,
        VirtualPath,
    };
    use ironclaw_skills::ManagedSkillSource;

    #[tokio::test]
    async fn owner_skill_list_reports_every_stored_user_skill() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage_root = dir.path().join("local-dev");
        for index in 0..55 {
            write_skill(&storage_root, &format!("list-skill-{index:02}"));
        }

        let skills = list_reborn_local_skills_for_owner(&test_port(&storage_root), test_scope())
            .await
            .expect("list owner skills");

        assert!(skills.iter().any(|skill| skill.name == "list-skill-54"));
        assert!(
            skills
                .iter()
                .filter(|skill| skill.name.starts_with("list-skill-"))
                .all(|skill| skill.source == ManagedSkillSource::User)
        );
    }

    #[test]
    fn bundled_skill_list_reports_embedded_system_skills() {
        let skills = list_reborn_bundled_skills().expect("list bundled skills");

        assert!(
            skills
                .iter()
                .any(|skill| skill.name == "code-review"
                    && skill.source == ManagedSkillSource::System)
        );
    }

    /// A user skill may shadow a bundled name. Both must survive: the user copy
    /// on the owner list, the bundled copy on the global list.
    #[tokio::test]
    async fn user_skill_and_bundled_duplicate_name_both_survive() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage_root = dir.path().join("local-dev");
        write_skill(&storage_root, "code-review");

        let owned = list_reborn_local_skills_for_owner(&test_port(&storage_root), test_scope())
            .await
            .expect("list owner skills");
        let bundled = list_reborn_bundled_skills().expect("list bundled skills");

        assert!(
            owned
                .iter()
                .any(|skill| skill.name == "code-review"
                    && skill.source == ManagedSkillSource::User)
        );
        assert!(
            bundled
                .iter()
                .any(|skill| skill.name == "code-review"
                    && skill.source == ManagedSkillSource::System)
        );
    }

    /// A stale system skill in storage must not shadow the embedded summary.
    #[tokio::test]
    async fn stored_system_skill_defers_to_embedded_bundled_summary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage_root = dir.path().join("local-dev");
        write_system_skill(&storage_root, "code-review", "old system description");
        let bundled_code_review = list_reborn_bundled_skills()
            .expect("list bundled skills")
            .into_iter()
            .find(|skill| skill.name == "code-review")
            .expect("bundled code-review");

        let owned = list_reborn_local_skills_for_owner(&test_port(&storage_root), test_scope())
            .await
            .expect("list owner skills");

        assert!(
            !owned.iter().any(|skill| skill.name == "code-review"
                && skill.source == ManagedSkillSource::System),
            "storage system skill must not duplicate the bundled summary"
        );
        assert_ne!(bundled_code_review.description, "old system description");
    }

    fn test_scope() -> ResourceScope {
        ResourceScope::local_default(
            UserId::new("list-owner").expect("valid user"),
            InvocationId::new(),
        )
        .expect("valid scope")
    }

    /// Mirrors the production local-dev skill mounts: user skills under
    /// `/tenants`, bundled system skills under `/system/skills`. Disk-backed here
    /// so the tests can seed by writing files.
    fn test_port(storage_root: &std::path::Path) -> ScopedSkillManagementPort {
        // `mount_local` requires the host directory to exist.
        std::fs::create_dir_all(storage_root.join("tenants")).expect("tenants root");
        std::fs::create_dir_all(storage_root.join("system/skills")).expect("system skills root");
        let mut filesystem = DiskFilesystem::new();
        filesystem
            .mount_local(
                VirtualPath::new("/tenants").expect("valid virtual path"),
                HostPath::from_path_buf(storage_root.join("tenants")),
            )
            .expect("mount tenants root");
        filesystem
            .mount_local(
                VirtualPath::new("/system/skills").expect("valid virtual path"),
                HostPath::from_path_buf(storage_root.join("system/skills")),
            )
            .expect("mount system skills root");
        ScopedSkillManagementPort::new_with_mount_resolver(
            UserId::new("list-owner").expect("valid user"),
            Arc::new(filesystem),
            Arc::new(|scope: &ResourceScope| {
                MountView::new(vec![
                    MountGrant::new(
                        MountAlias::new("/skills")?,
                        VirtualPath::new(format!(
                            "/tenants/{}/users/{}/skills",
                            scope.tenant_id.as_str(),
                            scope.user_id.as_str()
                        ))?,
                        MountPermissions::read_write_list_delete(),
                    ),
                    MountGrant::new(
                        MountAlias::new("/system/skills")?,
                        VirtualPath::new("/system/skills")?,
                        MountPermissions::read_only(),
                    ),
                ])
            }),
        )
    }

    fn write_skill(storage_root: &std::path::Path, name: &str) {
        let skill_dir = storage_root
            .join("tenants/default/users/list-owner/skills")
            .join(name);
        std::fs::create_dir_all(&skill_dir).expect("skill dir");
        std::fs::write(
            skill_dir.join("SKILL.md"),
            format!("---\nname: {name}\ndescription: list test\n---\nUse list.\n"),
        )
        .expect("skill file");
    }

    fn write_system_skill(storage_root: &std::path::Path, name: &str, description: &str) {
        let skill_dir = storage_root.join("system/skills").join(name);
        std::fs::create_dir_all(&skill_dir).expect("skill dir");
        std::fs::write(
            skill_dir.join("SKILL.md"),
            format!("---\nname: {name}\ndescription: {description}\n---\nUse system.\n"),
        )
        .expect("skill file");
    }
}
