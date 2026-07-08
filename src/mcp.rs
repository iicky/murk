//! In-process MCP (Model Context Protocol) stdio server — `murk mcp`.
//!
//! Serves murk secrets to AI-agent harnesses (omp, Claude Code, Cursor, ...)
//! over the MCP stdio transport, calling the murk-cli library in-process. The
//! caller-side security gate — this must be a scoped *grant* identity, not the
//! operator's key — lives in [`crate::cmd_mcp`]; by the time [`serve`] runs the
//! identity is already trusted and bounded to the grant's scope.
//!
//! stdout is the JSON-RPC channel: **never** write to it (no `println!`). Every
//! diagnostic goes to stderr via `tracing`. tokio is confined to this module —
//! the rest of murk stays synchronous.
//!
//! Tools (v1): `murk_plan` (value-free schema) and `murk_get` (scoped read that
//! fails closed on forbidden or out-of-scope keys).

use std::sync::Arc;

use murk_cli::types::{Murk, Vault};
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
    transport::stdio,
};
use schemars::JsonSchema;
use serde::Deserialize;

/// The decrypted, grant-scoped vault state the tools read from. Loaded once by
/// [`crate::cmd_mcp`] after the identity guard passes, then shared read-only for
/// the server's lifetime. Holds decrypted secret material (bounded to the grant),
/// so its lifetime is the connection's lifetime — the same tradeoff any
/// long-running secrets server makes.
pub struct McpState {
    pub vault: Vault,
    pub murk: Murk,
    /// The grant identity's public key — the reader `get_secret` resolves values
    /// for, and the subject of the agent-policy check.
    pub pubkey: String,
}

/// The murk MCP server handler. Cheap to clone — the state is behind an `Arc` and
/// the generated `#[tool_handler]` dispatch reads the router per request.
#[derive(Clone)]
pub struct MurkMcp {
    state: Arc<McpState>,
    tool_router: ToolRouter<Self>,
}

/// `murk_plan` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
struct PlanRequest {
    /// Optional tag filter. When non-empty, only keys carrying at least one of
    /// these tags are listed; omitted or empty lists the whole schema.
    #[serde(default)]
    tags: Vec<String>,
}

/// `murk_get` arguments.
#[derive(Debug, Deserialize, JsonSchema)]
struct GetRequest {
    /// The secret key name to read. Must be within this grant's scope and
    /// permitted by the vault's agent policy, or the call fails closed.
    key: String,
}

#[tool_router]
impl MurkMcp {
    fn new(state: Arc<McpState>) -> Self {
        Self {
            state,
            tool_router: Self::tool_router(),
        }
    }

    /// The secret *schema* for keys this grant may read — key names, descriptions,
    /// examples, tags — with no secret values. Bounded to the grant: only keys the
    /// grant can actually read *and* that the agent policy allows appear, so a
    /// scoped agent cannot enumerate out-of-scope key names or metadata.
    #[tool(
        description = "List the schema (key names, descriptions, examples, tags) of the secrets this grant may read, as JSON. Bounded to the grant's scope; never returns secret values."
    )]
    async fn murk_plan(
        &self,
        Parameters(PlanRequest { tags }): Parameters<PlanRequest>,
    ) -> Result<CallToolResult, McpError> {
        let st = &self.state;
        let mut plan = murk_cli::agent_plan(&st.vault, &tags);
        // Bound the plan to exactly the set murk_get would serve: keys allowed by
        // the agent policy AND readable under this grant. Without this a one-key
        // grant could enumerate every key's name/description/example/tags.
        plan.entries.retain(|e| {
            murk_cli::is_agent_key_allowed(&st.vault, &e.key)
                && murk_cli::get_secret(&st.murk, &e.key, &st.pubkey).is_some()
        });
        match serde_json::to_string_pretty(&plan) {
            Ok(json) => Ok(CallToolResult::success(vec![ContentBlock::text(json)])),
            Err(e) => Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "failed to render plan: {e}"
            ))])),
        }
    }

    /// Read one secret value by key. Fails closed: a key forbidden by the vault's
    /// agent policy, or outside this grant's scope, returns an error result —
    /// never the value.
    #[tool(
        description = "Read a single secret value by key. Fails closed: keys forbidden by the vault's agent policy or outside this grant's scope return an error, never the value."
    )]
    async fn murk_get(
        &self,
        Parameters(GetRequest { key }): Parameters<GetRequest>,
    ) -> Result<CallToolResult, McpError> {
        let st = &self.state;

        // Defense-in-depth policy gate: apply the vault's agent allow-tag policy
        // at read time (the cryptographic bound is the grant recipient set; this
        // refuses a forbidden key even if an old scoped ciphertext lingers).
        if let Err(e) = murk_cli::enforce_agent_policy(
            &st.vault,
            &st.murk,
            &st.pubkey,
            std::slice::from_ref(&key),
        ) {
            return Ok(CallToolResult::error(vec![ContentBlock::text(
                e.to_string(),
            )]));
        }

        match murk_cli::get_secret(&st.murk, &key, &st.pubkey) {
            Some(value) => Ok(CallToolResult::success(vec![ContentBlock::text(
                value.to_string(),
            )])),
            None => Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "{key}: not found or outside this grant's scope"
            ))])),
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for MurkMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("murk-mcp", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "murk secrets for AI agents, bounded to this grant's scope. Use murk_plan \
                 for the value-free schema and murk_get to read an in-scope key; both fail \
                 closed on anything outside the grant."
                    .to_string(),
            )
    }
}

/// Serve the MCP stdio server until the client disconnects (stdin EOF).
///
/// tokio is confined here via `#[tokio::main]`; the caller stays synchronous.
/// All logging is routed to stderr — stdout carries the JSON-RPC stream.
#[tokio::main]
pub async fn serve(state: McpState) -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    tracing::info!("murk mcp: serving over stdio");

    let service = MurkMcp::new(Arc::new(state))
        .serve(stdio())
        .await
        .inspect_err(|e| tracing::error!("murk mcp: failed to start: {e:?}"))?;

    service.waiting().await?;
    tracing::info!("murk mcp: client disconnected, shutting down");
    Ok(())
}

/// Install a stderr-only `tracing` subscriber. stdout is reserved for the
/// JSON-RPC transport, so log output must never land there. Best-effort: a
/// second call (or a subscriber already installed by a harness) is a no-op
/// rather than a panic.
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}
