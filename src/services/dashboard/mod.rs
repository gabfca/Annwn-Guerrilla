//! Dashboard service for monitoring node state and communication.
//!
//! This module provides a web-based dashboard served via Axum,
//! allowing users to inspect tables, uptime, communication events,
//! and a peer graph view of the node's known topology.

use crate::node::{knowledge::NodeKnowledgeHandler, Node};
use crate::{services::ServiceConfig, ServiceHandle};

use axum::{
    extract::Extension,
    http::{header, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, Router},
};
use axum_server::Server;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use std::default;
use std::path::PathBuf;
use std::{collections::HashMap, error::Error, net::SocketAddr, thread::JoinHandle};

use tower_http::services::ServeDir;

/// Configuration for the Dashboard service.
///
/// Implements the `ServiceConfig` trait.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct DashboardConfig;

impl<'sc> ServiceConfig<'sc> for DashboardConfig {
    /// Returns the service name.
    fn name() -> &'static str {
        "Dashboard"
    }

    /// Returns the port this service listens on.
    fn port() -> Option<u16> {
        Some(7879)
    }
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {}
    }
}

/// Dashboard state for handling routes and queries.
#[derive(Clone)]
pub struct Dashboard {
    knowledge_handler: NodeKnowledgeHandler,
    /// Node's initial configuration.
    pub init_config: crate::node::NodeInitConfig,
    running_config: crate::node::NodeRunningConfig,
}

impl Dashboard {
    /// Loads and processes the HTML template, replacing placeholders with node data.
    fn load_dashboard_template(
        path: &PathBuf,
        node_name: &str,
        node_ip: &str,
    ) -> Result<String, Box<dyn Error>> {
        let template = std::fs::read_to_string(path)?;
        Ok(template
            .replace("{node_name}", node_name)
            .replace("{node_ip}", node_ip))
    }

    /// Executes a SQL query via the knowledge handler, returning rows as `Vec<HashMap<String, String>>`.
    async fn execute_query(
        handler: NodeKnowledgeHandler,
        sql: String,
    ) -> Result<Vec<HashMap<String, String>>, Box<dyn Error>> {
        Ok(tokio::task::spawn_blocking(move || handler.query_sql(&sql)).await??)
    }

    /// Lists all non-system SQLite tables in the knowledge handler's database.
    async fn list_tables(handler: NodeKnowledgeHandler) -> Result<Vec<String>, Box<dyn Error>> {
        let rows = Dashboard::execute_query(
            handler,
            "SELECT name FROM sqlite_master WHERE type='table'".into(),
        )
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|r| r.get("name").cloned())
            .filter(|table| !table.starts_with("sqlite_"))
            .collect())
    }

    /// Gets all rows from a specified table, ordered by `rowid`.
    async fn get_table_rows(
        handler: NodeKnowledgeHandler,
        table_name: &str,
    ) -> Result<Vec<HashMap<String, String>>, Box<dyn Error>> {
        let sql = format!("SELECT * FROM {} ORDER BY rowid", table_name);
        Dashboard::execute_query(handler, sql).await
    }

    /// Handler for `/data` route: returns all table contents as JSON.
    async fn handle_data(
        Extension(dashboard): Extension<Dashboard>,
    ) -> Result<impl IntoResponse, (StatusCode, String)> {
        let tables = Dashboard::list_tables(dashboard.knowledge_handler.clone())
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let mut table_data = HashMap::new();

        for table in tables {
            let rows = Dashboard::get_table_rows(dashboard.knowledge_handler.clone(), &table)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            table_data.insert(table, rows);
        }

        Ok(axum::Json(table_data))
    }

    /// Handler for `/uptime` route: returns node uptime in seconds.
    async fn handle_uptime(
        Extension(dashboard): Extension<Dashboard>,
    ) -> Result<impl IntoResponse, (StatusCode, String)> {
        let now = Utc::now().timestamp();
        let uptime = now - dashboard.running_config.wake;

        Ok(axum::Json(serde_json::json!({ "uptime_seconds": uptime })))
    }

    /// Handler for `/graph` route: returns JSON for peer and self graph visualization.
    async fn handle_graph(
        Extension(dashboard): Extension<Dashboard>,
    ) -> Result<impl IntoResponse, (StatusCode, String)> {
        let mut nodes = vec![];
        let mut edges = vec![];

        let self_id = dashboard.init_config.name.clone();
        let self_ip = dashboard.running_config.ip.clone();

        nodes.push(serde_json::json!({
            "id": self_id,
            "label": self_id,
            "title": self_ip,
            "group": "self"
        }));

        let rows = Dashboard::execute_query(
            dashboard.knowledge_handler.clone(),
            "SELECT name, ip FROM known_nodes".into(),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        for row in rows {
            let peer_id = row.get("name").cloned().unwrap_or_default();
            let peer_ip = row.get("ip").cloned().unwrap_or_default();

            nodes.push(serde_json::json!({
                "id": peer_id,
                "label": format!("{}\n({})", peer_id, peer_ip),
                "title": peer_ip,
                "group": "peer"
            }));

            edges.push(serde_json::json!({
                "from": self_id,
                "to": peer_id,
                "label": ""
            }));
        }

        Ok(axum::Json(serde_json::json!({ "nodes": nodes, "edges": edges })))
    }

    /// Handler for `/comms` route: returns recent communication events.
    async fn handle_comms(
        Extension(dashboard): Extension<Dashboard>,
    ) -> Result<impl IntoResponse, (StatusCode, String)> {
        let rows = Dashboard::execute_query(
            dashboard.knowledge_handler.clone(),
            "SELECT * FROM comms_events ORDER BY received_at DESC LIMIT 100".into(),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        Ok(axum::Json(rows))
    }

    /// Handler for `/` route: returns HTML dashboard page.
    async fn handle_dashboard(
        Extension(dashboard): Extension<Dashboard>,
    ) -> Result<impl IntoResponse, (StatusCode, String)> {
        let template_file = PathBuf::from("src/services/dashboard/dashboard.html");

        let html = Dashboard::load_dashboard_template(
            &template_file,
            &dashboard.init_config.name,
            &dashboard.running_config.ip,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        Ok((
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            Html(html),
        ))
    }
}

/// Arguments passed into the dashboard when initializing it as a service.
pub struct DashboardArgs<'da> {
    /// Reference to the node running this service.
    pub node: &'da Node,
}

impl<'s> ServiceHandle<'s> for Dashboard {
    type Config = DashboardConfig;
    type Args = DashboardArgs<'s>;
    type Output = ();

    /// Starts the dashboard service as an Axum web server.
    fn run(
        _node: &crate::node::Node,
        _config: &Self::Config,
        args: Self::Args,
    ) -> Result<(Self::Output, JoinHandle<()>), Box<dyn Error>> {
        let dashboard = Dashboard {
            knowledge_handler: args.node.logger.clone(),
            init_config: args.node.init_config.clone(),
            running_config: args.node.running_config.clone(),
        };

        let app = Router::new()
            .nest_service("/logo", ServeDir::new("logo"))
            .route("/", get(Dashboard::handle_dashboard))
            .route("/data", get(Dashboard::handle_data))
            .route("/uptime", get(Dashboard::handle_uptime))
            .route("/graph", get(Dashboard::handle_graph))
            .route("/comms", get(Dashboard::handle_comms))
            .layer(Extension(dashboard));

        let addr = SocketAddr::from(([0, 0, 0, 0], DashboardConfig::port().unwrap()));
        let server = Server::bind(addr).serve(app.into_make_service());

        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime.");
            rt.block_on(server).expect("Server error.");
        });

        Ok(((), handle))
    }
}
