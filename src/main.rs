pub mod services;
pub mod node;

use std::{env, path::Path, sync::Arc, thread::JoinHandle};

use crate::services::{
    comms::{Comms, CommsConfig},
    dashboard::{Dashboard, DashboardConfig, DashboardArgs},
    discovery::{Discovery, DiscoveryArgs, DiscoveryConfig},
    flood_management::{FloodManagement, FloodManagementConfig},
    honeypot::{Honeypot, HoneypotConfig},
    ServiceHandle, ServiceConfig,
};

async fn spawn_services(
    node: &node::Node,
    config_path: &Path,
) -> Result<Vec<JoinHandle<()>>, Box<dyn std::error::Error>> {
    let mut handles = Vec::new();

    // Discovery service
    let discovery_config = DiscoveryConfig::load_from_file(config_path).unwrap_or_default();
    let ((known_nodes_handler, key), discovery_handle) =
        Discovery::run(node, &discovery_config, DiscoveryArgs {})?;
    handles.push(discovery_handle);

    // Comms service
    let comms_config = CommsConfig::load_from_file(config_path).unwrap_or_default();
    let (comms_channel_raw, comms_handle) =
        Comms::run(node, &comms_config, (&known_nodes_handler, Arc::new(key)))?;
    handles.push(comms_handle);
    let comms_channel = Arc::new(comms_channel_raw);

    // FloodManagement service
    let flood_mgmt_config = FloodManagementConfig::load_from_file(config_path).unwrap_or_else(|_| {
        let monitored_ports = vec![22, 80, 443];
        FloodManagementConfig::new(monitored_ports, None, None)
    });
    let (_, flood_mgmt_handle) =
        FloodManagement::run(node, &flood_mgmt_config, Arc::clone(&comms_channel))?;
    handles.push(flood_mgmt_handle);

    // Dashboard service
    let dashboard_config = DashboardConfig::load_from_file(config_path).unwrap_or_default();
    let ((), dashboard_handle) = Dashboard::run(node, &dashboard_config, DashboardArgs { node })?;
    handles.push(dashboard_handle);

    // Honeypot service
    let honeypot_config = HoneypotConfig::load_from_file(config_path).unwrap_or_else(|_| HoneypotConfig {
        directory: "/home/gabca/Projects/Honeypot/".to_string(),
    });
    let ((), honeypot_handle) = Honeypot::run(node, &honeypot_config, comms_channel)?;
    handles.push(honeypot_handle);

    Ok(handles)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get config file path from command line argument
    let config_path = env::args()
        .nth(1)
        .expect("Usage: app <config_file.toml>");
    let config_path = Path::new(&config_path);

    // Create node with the same config path
    let node = node::Node::new(config_path)?;

    let handles = spawn_services(&node, config_path).await?;

    for handle in handles {
        handle.join().unwrap();
    }

    Ok(())
}
