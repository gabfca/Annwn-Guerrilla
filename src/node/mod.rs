//! Node configuration and initialization module.
//!
//! This module provides structures and methods for managing node initialization
//! and runtime configuration, including persistence to disk.

pub mod knowledge;

use chrono::Utc;
use local_ip_address::local_ip;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::fs::create_dir_all;
use std::net::IpAddr;
use std::path::Path;

use knowledge::NodeKnowledgeHandler;

/// Directory name where running configuration files are stored
pub const RUNNING_CONFIG_DIRNAME: &str = "runs";

/// Initial configuration for a node, typically read from a config file.
#[derive(Deserialize, Debug, Clone)]
pub struct NodeInitConfig {
    /// Name of the node
    pub name: String,
}

impl NodeInitConfig {
    /// Reads node initialization configuration from the [node] section of a unified TOML config file.
    ///
    /// # Arguments
    ///
    /// * `filepath` - Path to the configuration file
    ///
    /// # Returns
    ///
    /// A `Result` containing the parsed `NodeInitConfig` or an error
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be read
    /// - The TOML is invalid
    /// - The [node] section is missing
    /// - The [node] section contains invalid data
    pub(crate) fn read_from(filepath: &Path) -> Result<NodeInitConfig, Box<dyn Error>> {
        let content = fs::read_to_string(filepath)?;
        let full_config: toml::Value = toml::from_str(&content)?;

        // Extract the [node] section
        let node_section = full_config
            .get("node")
            .ok_or("Missing [node] section in config")?;

        // Deserialize only the [node] section into NodeInitConfig
        let config: NodeInitConfig = node_section.clone().try_into()?;

        Ok(config)
    }
}

/// Runtime configuration for a node, persisted during operation.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct NodeRunningConfig {
    /// IP address of the node
    pub ip: String,
    /// Timestamp when the node was started (woke up)
    pub wake: i64,
}

impl NodeRunningConfig {
    /// Reads running configuration from a TOML file.
    ///
    /// # Arguments
    ///
    /// * `filepath` - Path to the configuration file
    ///
    /// # Returns
    ///
    /// A `Result` containing the parsed `NodeRunningConfig` or an error
    pub(crate) fn read_from(filepath: &Path) -> Result<NodeRunningConfig, Box<dyn Error>> {
        let content = fs::read_to_string(filepath)?;
        let config: NodeRunningConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Generates a new running configuration and writes it to a file.
    ///
    /// # Arguments
    ///
    /// * `ip` - IP address of the node
    ///
    /// # Returns
    ///
    /// A `Result` containing the new `NodeRunningConfig` or an error
    ///
    /// # Notes
    ///
    /// - Creates the runs directory if it doesn't exist
    /// - Generates a filename based on current timestamp
    /// - Writes configuration in pretty-printed TOML format
    pub(crate) fn generate(ip: IpAddr) -> Result<NodeRunningConfig, Box<dyn Error>> {
        let now = Utc::now();

        let config = NodeRunningConfig {
            ip: ip.to_string(),
            wake: now.timestamp(),
        };

        create_dir_all(RUNNING_CONFIG_DIRNAME)?;

        let filename = format!("{}.toml", now.format("%Y%m%d_%H%M%S"));
        let full_path = Path::new(RUNNING_CONFIG_DIRNAME).join(&filename);

        let toml_string = toml::to_string_pretty(&config)?;
        fs::write(&full_path, toml_string)?;

        println!("Config written to: {}", full_path.display());

        Ok(config)
    }
}

/// Main node structure combining configuration and services.
#[derive(Clone)]
pub struct Node {
    /// Initial configuration of the node
    pub init_config: NodeInitConfig,
    /// Runtime configuration of the node
    pub running_config: NodeRunningConfig,
    /// Knowledge handler for the node
    pub logger: NodeKnowledgeHandler,
}

impl Node {
    /// Creates a new node instance.
    ///
    /// # Arguments
    ///
    /// * `init_config_path` - Path to the initialization configuration file
    ///
    /// # Returns
    ///
    /// A `Result` containing the new `Node` or an error
    ///
    /// # Behavior
    ///
    /// 1. Reads the initialization configuration
    /// 2. Attempts to load the most recent running configuration
    /// 3. If no running config exists, generates a new one with current IP
    /// 4. Initializes the knowledge handler
    pub fn new(init_config_path: &Path) -> Result<Self, Box<dyn Error>> {
        let init_config = NodeInitConfig::read_from(init_config_path)?;

        // Try to read existing running config files from RUNNING_CONFIG_DIRNAME.
        // Pick the latest file if there are multiple.
        let running_config = {
            let dir = Path::new(RUNNING_CONFIG_DIRNAME);
            if dir.exists() {
                let mut entries: Vec<_> = fs::read_dir(dir)?
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().map_or(false, |ext| ext == "toml"))
                    .collect();

                entries.sort_by_key(|e| e.file_name());

                if let Some(latest_file) = entries.last() {
                    // Read config from latest file
                    if let Ok(cfg) = NodeRunningConfig::read_from(&latest_file.path()) {
                        Some(cfg)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        };

        let running_config = match running_config {
            Some(cfg) => cfg,
            None => NodeRunningConfig::generate(local_ip()?)?,
        };

        let logger = NodeKnowledgeHandler::new()?;

        Ok(Node {
            init_config,
            running_config,
            logger,
        })
    }
}