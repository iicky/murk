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
//! The tools themselves (`murk_plan`, `murk_get`) arrive in murk-qu2.5.2; this
//! scaffold serves the MCP `initialize` handshake and an (empty) `tools/list`.

use rmcp::{
    ServerHandler, ServiceExt,
    model::{Implementation, ServerCapabilities, ServerInfo},
    transport::stdio,
};

/// The murk MCP server handler.
///
/// A unit type for now: this scaffold advertises the `tools` capability and
/// serves an empty `tools/list` (the `ServerHandler` defaults). The real tools
/// (`murk_plan`, `murk_get`) and the vault state they read arrive in
/// murk-qu2.5.2, which swaps this for the `#[tool_router]` / `#[tool_handler]`
/// machinery.
#[derive(Clone)]
pub struct MurkMcp;

impl ServerHandler for MurkMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("murk-mcp", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "murk secrets for AI agents, bounded to this grant's scope. Tools \
                 fail closed on anything outside the grant."
                    .to_string(),
            )
    }

    // `list_tools` defaults to an empty list and `call_tool` to method-not-found
    // until murk-qu2.5.2 registers `murk_plan` + `murk_get`.
}

/// Serve the MCP stdio server until the client disconnects (stdin EOF).
///
/// tokio is confined here via `#[tokio::main]`; the caller stays synchronous.
/// All logging is routed to stderr — stdout carries the JSON-RPC stream.
#[tokio::main]
pub async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    tracing::info!("murk mcp: serving over stdio");

    let service = MurkMcp
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
