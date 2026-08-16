use clap::{Args, Subcommand};
use ironclaw_extension_host::skill_listing::list_reborn_bundled_skills;
use ironclaw_reborn_composition::{
    RebornSkillSummary, host_api::AgentId, host_api::TenantId, host_api::UserId,
    open_skill_listing_source, reborn_skill_summary_json,
};
use ironclaw_reborn_config::{RebornBootConfig, RebornProfile};
use std::path::PathBuf;

use crate::context::RebornCliContext;

/// Skills for one `(tenant, user)`. `owner` is `None` for the bundled system
/// skills, which are global rather than owned by a user.
struct SkillGroup {
    owner: Option<(String, String)>,
    skills: Vec<RebornSkillSummary>,
}

#[derive(Debug, Args)]
pub(crate) struct SkillsCommand {
    #[command(subcommand)]
    command: SkillsSubcommand,
}

#[derive(Debug, Subcommand)]
enum SkillsSubcommand {
    /// List configured Reborn skills.
    List(SkillsListCommand),
}

#[derive(Debug, Args)]
struct SkillsListCommand {
    /// Show extra status details.
    #[arg(short, long)]
    verbose: bool,

    /// Output skills as JSON.
    #[arg(long)]
    json: bool,

    /// Only list skills owned by this tenant.
    #[arg(long)]
    tenant: Option<String>,

    /// Only list skills owned by this user.
    #[arg(long)]
    user: Option<String>,
}

impl SkillsCommand {
    pub(crate) fn execute(self, context: RebornCliContext) -> anyhow::Result<()> {
        match self.command {
            SkillsSubcommand::List(command) => command.execute(context),
        }
    }
}

impl SkillsListCommand {
    fn execute(self, context: RebornCliContext) -> anyhow::Result<()> {
        let (config, config_file) = build_skill_list_config(context.boot_config())?;
        let filter = SkillOwnerFilter {
            tenant: self.tenant.clone(),
            user: self.user.clone(),
        };
        let groups = crate::runtime::block_on_cli(collect_skill_groups(
            config.clone(),
            config_file,
            filter.clone(),
        ))?;
        let configured = groups.iter().map(|group| group.skills.len()).sum::<usize>();
        // A filter matching nothing is usually a typo, not an empty store.
        if !filter.is_empty() && groups.is_empty() {
            eprintln!(
                "warning: no skill owner matches {}; run without --tenant/--user to list known owners",
                crate::render::terminal_safe_text(&filter.describe())
            );
        }

        if self.json {
            let mut output = skills_json(configured, &groups);
            if self.verbose {
                output["details"] = serde_json::json!({
                    "profile": config.profile.to_string(),
                    "reborn_home": context.boot_config().home().path(),
                    "local_dev_root": config.local_dev_root,
                    "owner_id": config.owner_id,
                });
            }
            println!("{}", output);
            return Ok(());
        }

        println!("IronClaw Reborn skills");
        println!("configured: {configured}");
        println!("source: reborn-local-dev");

        if self.verbose {
            println!("profile: {}", config.profile);
            println!(
                "reborn_home: {}",
                context.boot_config().home().path().display()
            );
            println!("local_dev_root: {}", config.local_dev_root.display());
            println!("owner_id: {}", config.owner_id);
        }

        for group in groups {
            println!();
            println!("{}", group_heading(&group));
            for skill in &group.skills {
                print_skill(skill, self.verbose);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
struct SkillOwnerFilter {
    tenant: Option<String>,
    user: Option<String>,
}

impl SkillOwnerFilter {
    fn is_empty(&self) -> bool {
        self.tenant.is_none() && self.user.is_none()
    }

    fn matches(&self, tenant: &str, user: &str) -> bool {
        self.tenant.as_deref().is_none_or(|value| value == tenant)
            && self.user.as_deref().is_none_or(|value| value == user)
    }

    fn describe(&self) -> String {
        match (self.tenant.as_deref(), self.user.as_deref()) {
            (Some(tenant), Some(user)) => format!("tenant {tenant} / user {user}"),
            (Some(tenant), None) => format!("tenant {tenant}"),
            (None, Some(user)) => format!("user {user}"),
            (None, None) => "no filter".to_string(),
        }
    }
}

/// Bundled skills first, then one group per owner the store knows about.
/// Owners are discovered rather than assumed: the CLI cannot know which users
/// exist, because WebUI login mints them at runtime.
async fn collect_skill_groups(
    config: SkillListConfig,
    config_file: Option<ironclaw_reborn_config::RebornConfigFile>,
    filter: SkillOwnerFilter,
) -> anyhow::Result<Vec<SkillGroup>> {
    let mut groups = Vec::new();
    if filter.is_empty() {
        groups.push(SkillGroup {
            owner: None,
            skills: list_reborn_bundled_skills()?,
        });
    }

    let tenant_id = TenantId::new(config.tenant_id)
        .map_err(|error| anyhow::anyhow!("invalid runtime tenant identity: {error}"))?;
    let agent_id = AgentId::new(config.agent_id)
        .map_err(|error| anyhow::anyhow!("invalid runtime agent identity: {error}"))?;
    let owner_id = UserId::new(config.owner_id)
        .map_err(|error| anyhow::anyhow!("invalid runtime owner identity: {error}"))?;
    let Some(source) = open_skill_listing_source(
        &config.local_dev_root,
        config.composition_profile,
        config_file.as_ref(),
        tenant_id,
        agent_id,
        owner_id,
    )
    .await?
    else {
        return Ok(groups);
    };

    for owner in source.owners() {
        let tenant = owner.tenant_id.as_str().to_string();
        let user = owner.user_id.as_str().to_string();
        if !filter.matches(&tenant, &user) {
            continue;
        }
        let skills = source.list_for_owner(owner).await?;
        if skills.is_empty() && filter.is_empty() {
            continue;
        }
        groups.push(SkillGroup {
            owner: Some((tenant, user)),
            skills,
        });
    }
    Ok(groups)
}

fn group_heading(group: &SkillGroup) -> String {
    match &group.owner {
        None => "bundled".to_string(),
        Some((tenant, user)) => format!(
            "tenant {} / user {}",
            crate::render::terminal_safe_text(tenant),
            crate::render::terminal_safe_text(user)
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SkillListConfig {
    owner_id: String,
    tenant_id: String,
    agent_id: String,
    local_dev_root: PathBuf,
    profile: RebornProfile,
    composition_profile: ironclaw_reborn_composition::RebornCompositionProfile,
}

/// Returns the config file alongside the resolved config: the hosted
/// single-tenant skill store is Postgres, and its connection lives there.
fn build_skill_list_config(
    config: &RebornBootConfig,
) -> anyhow::Result<(
    SkillListConfig,
    Option<ironclaw_reborn_config::RebornConfigFile>,
)> {
    let config_file = crate::runtime::read_config_file(config)?;
    let profile = crate::runtime::effective_profile(config, config_file.as_ref())?;
    if !profile.supports_local_runtime_skill_management() {
        anyhow::bail!(
            "ironclaw skills currently supports profile=local-dev, profile=local-dev-yolo, profile=hosted-single-tenant, or profile=hosted-single-tenant-volume; got profile={profile}"
        );
    }
    let identity = crate::runtime::runtime_identity(config_file.as_ref());
    Ok((
        SkillListConfig {
            owner_id: crate::runtime::default_owner_id(config_file.as_ref()).to_string(),
            tenant_id: identity.tenant_id,
            agent_id: identity.agent_id,
            local_dev_root: crate::runtime::local_runtime_storage_root(config, profile),
            profile,
            composition_profile: crate::runtime::composition_profile(profile),
        },
        config_file,
    ))
}

fn print_skill(skill: &RebornSkillSummary, verbose: bool) {
    println!(
        "- {} ({})",
        crate::render::terminal_safe_text(&skill.name),
        skill.source.as_str()
    );
    if !skill.description.is_empty() {
        println!(
            "  description: {}",
            crate::render::terminal_safe_text(&skill.description)
        );
    }
    if verbose {
        if !skill.version.is_empty() {
            println!(
                "  version: {}",
                crate::render::terminal_safe_text(&skill.version)
            );
        }
        print_list_field("keywords", &skill.keywords);
        print_list_field("tags", &skill.tags);
        print_list_field("requires_skills", &skill.requires_skills);
    }
}

fn print_list_field(label: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    let safe_values = values
        .iter()
        .map(|value| crate::render::terminal_safe_text(value))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if !safe_values.is_empty() {
        println!("  {label}: {}", safe_values.join(", "));
    }
}

fn skills_json(configured: usize, groups: &[SkillGroup]) -> serde_json::Value {
    let skills = groups
        .iter()
        .flat_map(|group| {
            group.skills.iter().map(|skill| {
                let mut value = reborn_skill_summary_json(skill);
                let (tenant, user) = match &group.owner {
                    None => (serde_json::Value::Null, serde_json::Value::Null),
                    Some((tenant, user)) => (
                        serde_json::Value::from(tenant.clone()),
                        serde_json::Value::from(user.clone()),
                    ),
                };
                value["tenant"] = tenant;
                value["user"] = user;
                value
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "configured": configured,
        "skills": skills,
        "source": "reborn-local-dev",
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn terminal_safe_text_replaces_control_characters() {
        assert_eq!(
            crate::render::terminal_safe_text("safe\nforged: row\u{1b}[31m"),
            "safe forged: row [31m"
        );
    }
}
