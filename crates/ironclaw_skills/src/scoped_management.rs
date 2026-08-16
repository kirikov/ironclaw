use std::sync::Arc;

use ironclaw_filesystem::RootFilesystem;
use ironclaw_host_api::{HostApiError, InvocationId, MountView, ResourceScope, UserId};

use crate::{
    SkillContentRequest, SkillContentResult, SkillInstallRequest, SkillInstallResult,
    SkillInstallSource, SkillManagementContext, SkillManagementError, SkillRemoveRequest,
    SkillRemoveResult, SkillSearchRequest, SkillSearchResult, SkillSummary, SkillUpdateRequest,
    SkillUpdateResult, install_skill, list_skills, read_skill_content, remove_skill, search_skills,
    update_skill,
};

pub type ScopedSkillManagementMountResolver =
    dyn Fn(&ResourceScope) -> Result<MountView, HostApiError> + Send + Sync;

#[derive(Clone)]
pub struct ScopedSkillManagementPort {
    owner_user_id: UserId,
    filesystem: Arc<dyn RootFilesystem>,
    mount_resolver: Arc<ScopedSkillManagementMountResolver>,
}

impl ScopedSkillManagementPort {
    pub fn new(
        owner_user_id: UserId,
        filesystem: Arc<dyn RootFilesystem>,
        mounts: MountView,
    ) -> Self {
        let resolver = Arc::new(move |_scope: &ResourceScope| Ok(mounts.clone()));
        Self::new_with_mount_resolver(owner_user_id, filesystem, resolver)
    }

    pub fn new_with_mount_resolver(
        owner_user_id: UserId,
        filesystem: Arc<dyn RootFilesystem>,
        mount_resolver: Arc<ScopedSkillManagementMountResolver>,
    ) -> Self {
        Self {
            owner_user_id,
            filesystem,
            mount_resolver,
        }
    }

    /// The scope->mount-view resolver this port was composed with. Product
    /// capability invokers reuse it so skill-management gestures dispatched
    /// through the product surface resolve the same mounts the agent-loop skill
    /// tools do.
    pub fn mount_resolver(&self) -> Arc<ScopedSkillManagementMountResolver> {
        Arc::clone(&self.mount_resolver)
    }

    pub fn owner_scope(&self) -> Result<ResourceScope, ScopedSkillManagementError> {
        ResourceScope::local_default(self.owner_user_id.clone(), InvocationId::new())
            .map_err(invalid_skill_context)
    }

    fn context_for_scope(
        &self,
        scope: ResourceScope,
    ) -> Result<SkillManagementContext, ScopedSkillManagementError> {
        let mounts = (self.mount_resolver)(&scope).map_err(invalid_skill_context)?;
        Ok(SkillManagementContext::new(
            self.filesystem.clone(),
            mounts,
            scope,
        ))
    }

    pub async fn list_for_scope(
        &self,
        scope: ResourceScope,
    ) -> Result<Vec<SkillSummary>, ScopedSkillManagementError> {
        let context = self.context_for_scope(scope)?;
        Ok(list_skills(&context).await?)
    }

    pub async fn search_for_scope(
        &self,
        scope: ResourceScope,
        query: &str,
        limit: usize,
    ) -> Result<SkillSearchResult, ScopedSkillManagementError> {
        let context = self.context_for_scope(scope)?;
        Ok(search_skills(&context, SkillSearchRequest { query, limit }).await?)
    }

    pub async fn read_content_for_scope(
        &self,
        scope: ResourceScope,
        name: &str,
    ) -> Result<SkillContentResult, ScopedSkillManagementError> {
        let context = self.context_for_scope(scope)?;
        Ok(read_skill_content(&context, SkillContentRequest { name }).await?)
    }

    pub async fn update_for_scope(
        &self,
        scope: ResourceScope,
        name: &str,
        content: &str,
    ) -> Result<SkillUpdateResult, ScopedSkillManagementError> {
        let context = self.context_for_scope(scope)?;
        Ok(update_skill(&context, SkillUpdateRequest { name, content }).await?)
    }

    pub async fn install_for_scope(
        &self,
        scope: ResourceScope,
        name: Option<&str>,
        content: &str,
    ) -> Result<SkillInstallResult, ScopedSkillManagementError> {
        let context = self.context_for_scope(scope)?;
        Ok(install_skill(
            &context,
            SkillInstallRequest {
                name,
                content,
                files: &[],
                source: SkillInstallSource::User,
                source_url: None,
            },
        )
        .await?)
    }

    pub async fn remove_for_scope(
        &self,
        scope: ResourceScope,
        name: &str,
    ) -> Result<SkillRemoveResult, ScopedSkillManagementError> {
        let context = self.context_for_scope(scope)?;
        Ok(remove_skill(&context, SkillRemoveRequest { name }).await?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScopedSkillManagementError {
    #[error("invalid skill management context: {reason}")]
    InvalidContext { reason: String },
    #[error("skill management failed: {0:?}")]
    Skill(SkillManagementError),
}

impl From<SkillManagementError> for ScopedSkillManagementError {
    fn from(error: SkillManagementError) -> Self {
        Self::Skill(error)
    }
}

fn invalid_skill_context(error: impl std::fmt::Display) -> ScopedSkillManagementError {
    ScopedSkillManagementError::InvalidContext {
        reason: error.to_string(),
    }
}
