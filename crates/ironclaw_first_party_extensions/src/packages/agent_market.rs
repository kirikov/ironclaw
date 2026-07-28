//! Agent Market MCP package — agent.market marketplace tools (search/hire/jobs)
//! over a hosted MCP server, api-key credential delivered per user at
//! provisioning, host-mediated egress. Assets: per-tool input JSON schemas
//! (no bundled WASM; dispatched via MCP).
//!
//! The bundled manifest carries a `MARKET_PUBLIC_HOST` placeholder in
//! `[mcp].server`; [`bundle`] substitutes the deployment's marketplace origin
//! from `AGENT_MARKET_MCP_URL` (e.g. `https://market.example.com/mcp`). The
//! connection credential's audience is derived from the server host by the
//! v3 manifest normalizer, so the one substitution re-targets credential
//! injection too. Without the env var the placeholder stays — the catalog
//! entry is present but its server is unreachable, matching a deployment
//! that has no marketplace. A SET-but-malformed value fails loudly at
//! startup: silently shipping a corrupted manifest would surface only as
//! the extension mysteriously failing to load much later.

use std::borrow::Cow;

use ironclaw_host_api::EffectKind;

use super::{PackageBundle, PackageOnboarding, bytes_asset};

pub(super) const ID: &str = "agent-market";

const MANIFEST: &str = include_str!("../../assets/agent-market/manifest.toml");

/// Deployment-time override for the marketplace MCP origin.
const SERVER_URL_ENV: &str = "AGENT_MARKET_MCP_URL";

/// The placeholder the shipped manifest carries in `[mcp].server`.
const SERVER_URL_PLACEHOLDER: &str = "https://MARKET_PUBLIC_HOST/mcp";

/// Validate the operator-supplied server URL before splicing it into TOML
/// source. The value lands inside a TOML string literal, so an unvalidated
/// `"` would break out of the literal and inject keys, and a `#` would
/// comment out the rest of the line — both silently corrupting the manifest.
/// Requirements mirror what the hosted-MCP endpoint parser accepts: https,
/// host, no userinfo/query/fragment. Panics with a message naming the env
/// var — a set-but-malformed value is an operator error, and failing at
/// startup beats an extension that mysteriously never loads.
fn validated_server_url(raw: &str) -> &str {
    let trimmed = raw.trim();
    let parsed = url::Url::parse(trimmed).unwrap_or_else(|error| {
        panic!("{SERVER_URL_ENV} is not a valid URL ({error}): {trimmed:?}")
    });
    let ok = parsed.scheme() == "https"
        && parsed.host_str().is_some()
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && !trimmed.contains(['"', '#', '\\'])
        && !trimmed.chars().any(char::is_whitespace);
    assert!(
        ok,
        "{SERVER_URL_ENV} must be a plain https URL (host + path only, no \
         userinfo/query/fragment or TOML-significant characters): {trimmed:?}"
    );
    trimmed
}

pub(super) fn bundle() -> PackageBundle {
    let manifest_toml = match std::env::var(SERVER_URL_ENV) {
        Ok(url) if !url.trim().is_empty() => {
            Cow::Owned(MANIFEST.replace(SERVER_URL_PLACEHOLDER, validated_server_url(&url)))
        }
        _ => Cow::Borrowed(MANIFEST),
    };
    // The `manifest.toml` asset must carry the SAME (possibly env-patched)
    // bytes the package validates with: install materializes the assets into
    // the extension dir, and a divergent copy would change the manifest hash
    // the installation records pin.
    let assets = assets(manifest_toml.as_bytes());
    PackageBundle {
        id: ID,
        display_name: "Agent Market",
        manifest_toml,
        assets,
        onboarding: Some(PackageOnboarding {
            instructions: "Agent Market needs the marketplace-issued API token before its \
                search and hire tools can run."
                .to_string(),
            credential_instructions: Some(
                "Paste the `axm_` bearer the marketplace issued for this account. Managed \
                deployments deliver it automatically at provisioning."
                    .to_string(),
            ),
            setup_url: None,
            credential_next_step: "After saving the token, IronClaw finishes Agent Market \
                installation automatically and publishes its MCP tools."
                .to_string(),
        }),
        // MCP api-key extension: Dispatch + Network + UseSecret + ExternalWrite
        // (hire/submit mutate marketplace state) — same shape as Notion MCP.
        trust_effects: Some(vec![
            EffectKind::DispatchCapability,
            EffectKind::Network,
            EffectKind::UseSecret,
            EffectKind::ExternalWrite,
        ]),
    }
}

fn assets(manifest: &[u8]) -> Vec<super::PackageAsset> {
    macro_rules! agent_market_schema_asset {
        ($path:literal) => {
            bytes_asset(
                concat!("schemas/", $path),
                include_bytes!(concat!("../../assets/agent-market/schemas/", $path)),
            )
        };
    }

    vec![
        bytes_asset("manifest.toml", manifest),
        agent_market_schema_asset!("search_agents.input.v1.json"),
        agent_market_schema_asset!("hire_agent.input.v1.json"),
        agent_market_schema_asset!("create_job.input.v1.json"),
        agent_market_schema_asset!("get_job_result.input.v1.json"),
        agent_market_schema_asset!("submit_deliverable.input.v1.json"),
        agent_market_schema_asset!("read_messages.input.v1.json"),
        agent_market_schema_asset!("list_jobs.input.v1.json"),
        agent_market_schema_asset!("cancel_job.input.v1.json"),
    ]
}

#[cfg(test)]
mod tests {
    use super::validated_server_url;

    #[test]
    fn accepts_a_plain_https_url() {
        assert_eq!(
            validated_server_url(" https://market.example.com/mcp "),
            "https://market.example.com/mcp"
        );
    }

    /// A quote would break out of the TOML string literal and inject keys
    /// into the `[mcp]` table — the exact corruption the validator exists for.
    #[test]
    #[should_panic(expected = "AGENT_MARKET_MCP_URL")]
    fn rejects_toml_string_breakout() {
        validated_server_url("https://market.example.com/mcp\"\nhack = \"1");
    }

    /// A `#` would turn the rest of the manifest line into a TOML comment,
    /// silently dropping the keys that follow.
    #[test]
    #[should_panic(expected = "AGENT_MARKET_MCP_URL")]
    fn rejects_comment_truncation() {
        validated_server_url("https://market.example.com/mcp#");
    }

    #[test]
    #[should_panic(expected = "AGENT_MARKET_MCP_URL")]
    fn rejects_non_https() {
        validated_server_url("http://market.example.com/mcp");
    }
}
