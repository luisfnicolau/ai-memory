//! `ai-memory grant` — manage who may reach which repository (#708).
//!
//! Thin HTTP client over `/admin/grants*`. The caller's bearer token must
//! authenticate as root, the same as `ai-memory user`: grants are an operator
//! action, and the server is usually somewhere the operator's laptop cannot
//! open the database directly.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::cli::{GrantAddArgs, GrantArgs, GrantCommand, GrantListArgs, GrantTargetArgs};
use crate::config::Config;
use crate::http_client::{ServerEndpoint, get_json, post_json};

/// Dispatch a `grant` subcommand.
///
/// # Errors
/// Transport failures, a non-root token, or an unknown user or repository.
pub async fn run(config: &Config, args: GrantArgs) -> Result<()> {
    let ep = ServerEndpoint::from_config_resolving_auth(config).await;
    match args.command {
        GrantCommand::List(args) => list(&ep, args).await,
        GrantCommand::Add(args) => add(&ep, args).await,
        GrantCommand::Revoke(args) => revoke(&ep, args).await,
        GrantCommand::Seed => seed(&ep).await,
    }
}

#[derive(Debug, Serialize)]
struct GrantRequest<'a> {
    username: &'a str,
    workspace: &'a str,
    project: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<&'a str>,
}

impl<'a> GrantRequest<'a> {
    fn new(target: &'a GrantTargetArgs, role: Option<&'a str>) -> Self {
        Self {
            username: &target.username,
            workspace: &target.workspace,
            project: &target.project,
            role,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct GrantRow {
    username: String,
    workspace: String,
    project: String,
    role: String,
}

#[derive(Debug, Deserialize)]
struct GrantList {
    grants: Vec<GrantRow>,
}

async fn list(ep: &ServerEndpoint, args: GrantListArgs) -> Result<()> {
    let resp: GrantList = get_json(ep, "/admin/grants", &[])
        .await
        .context("listing grants")?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&resp.grants)?);
        return Ok(());
    }
    if resp.grants.is_empty() {
        // Say what empty means, because it means two very different things
        // depending on a setting this command cannot see.
        println!("(no grants in force)");
        println!(
            "With [auth].authorization = false nothing is enforced and every user reaches \
             every repository. With it on, nobody but root reaches anything."
        );
        return Ok(());
    }
    let repo_w = resp
        .grants
        .iter()
        .map(|g| g.workspace.len() + 1 + g.project.len())
        .max()
        .unwrap_or(10)
        .max(10);
    let user_w = resp
        .grants
        .iter()
        .map(|g| g.username.len())
        .max()
        .unwrap_or(8)
        .max(8);
    println!("{:<repo_w$}  {:<user_w$}  ROLE", "REPOSITORY", "USERNAME");
    for g in &resp.grants {
        let repo = format!("{}/{}", g.workspace, g.project);
        println!("{repo:<repo_w$}  {:<user_w$}  {}", g.username, g.role);
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct GrantResponse {
    role: String,
    changed: bool,
    previous: Option<String>,
}

async fn add(ep: &ServerEndpoint, args: GrantAddArgs) -> Result<()> {
    let body = GrantRequest::new(&args.target, Some(&args.role));
    let resp: GrantResponse = post_json(ep, "/admin/grants", &body)
        .await
        .with_context(|| {
            format!(
                "granting {} on {}/{}",
                args.target.username, args.target.workspace, args.target.project
            )
        })?;
    let who = &args.target.username;
    let repo = format!("{}/{}", args.target.workspace, args.target.project);
    match (resp.changed, resp.previous) {
        (false, _) => println!(
            "{who} already holds {} on {repo}; nothing changed.",
            resp.role
        ),
        (true, Some(previous)) => {
            println!("{who}: {previous} -> {} on {repo}.", resp.role);
        }
        (true, None) => println!("{who} now holds {} on {repo}.", resp.role),
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct RevokeResponse {
    revoked: bool,
}

async fn revoke(ep: &ServerEndpoint, args: GrantTargetArgs) -> Result<()> {
    let body = GrantRequest::new(&args, None);
    let resp: RevokeResponse = post_json(ep, "/admin/grants/revoke", &body)
        .await
        .with_context(|| {
            format!(
                "revoking {} on {}/{}",
                args.username, args.workspace, args.project
            )
        })?;
    let repo = format!("{}/{}", args.workspace, args.project);
    if resp.revoked {
        println!("{} no longer holds anything on {repo}.", args.username);
    } else {
        println!("{} held nothing on {repo}; nothing changed.", args.username);
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct SeedResponse {
    granted: usize,
    already_held: usize,
    users: usize,
    repositories: usize,
}

async fn seed(ep: &ServerEndpoint) -> Result<()> {
    let resp: SeedResponse = post_json(ep, "/admin/grants/seed", &serde_json::json!({}))
        .await
        .context("seeding grants")?;
    println!(
        "Seeded {} admin grant(s) across {} user(s) and {} repositor(y/ies); \
         {} pair(s) already held a grant and were left as they were.",
        resp.granted, resp.users, resp.repositories, resp.already_held
    );
    println!();
    println!("Existing access is preserved. Next:");
    println!("  1. set [auth].authorization = true and restart the server");
    println!("  2. ai-memory grant list, then grant revoke / grant add to narrow it");
    Ok(())
}
