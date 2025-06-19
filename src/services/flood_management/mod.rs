/// Flood management module for DDoS detection and mitigation.
///
/// This module defines the configuration and runtime behavior
/// of services responsible for detecting and blocking flood attacks,
/// using modular subcomponents for detection and blocking.
pub mod blocking;
pub mod detection;

use std::{
    error::Error,
    sync::{mpsc, Arc},
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::{
    node::Node,
    services::{comms::CommsEvent, ServiceConfig, ServiceHandle},
};

use blocking::{FloodBlocking, FloodBlockingConfig};
use detection::{FloodDetection, FloodDetectionConfig, Sensitivity};
use serde::{Deserialize, Serialize};

/// Configuration for the flood management service.
///
/// This structure holds configurations for both the detection and
/// blocking subsystems, allowing customization of how the system
/// detects and reacts to flood events.
#[derive(Clone, Serialize, Deserialize)]
pub struct FloodManagementConfig {
    /// Configuration for flood detection parameters.
    pub detection: FloodDetectionConfig,

    /// Configuration for flood blocking behavior.
    pub blocking: FloodBlockingConfig,
}

impl Default for FloodManagementConfig {
    fn default() -> Self {
        Self {
            detection: FloodDetectionConfig::default(),
            blocking: FloodBlockingConfig::default(),
        }
    }
}

impl FloodManagementConfig {
    /// Creates a new `FloodManagementConfig` with optional custom configurations.
    ///
    /// # Arguments
    ///
    /// * `monitored_ports` - Ports to monitor for flooding behavior.
    /// * `detection_config` - Optional custom detection configuration.
    /// * `blocking_config` - Optional custom blocking configuration.
    ///
    /// # Returns
    ///
    /// A new `FloodManagementConfig` with provided or default settings.
    pub fn new(
        monitored_ports: Vec<u16>,
        detection_config: Option<FloodDetectionConfig>,
        blocking_config: Option<FloodBlockingConfig>,
    ) -> Self {
        let detection = detection_config
            .unwrap_or_else(|| FloodDetectionConfig::medium(monitored_ports.clone()));

        let blocking = blocking_config.unwrap_or_else(|| FloodBlockingConfig {
            block_duration: Duration::from_secs(300),
            iptables_chain: "INPUT".to_string(),
        });

        Self {
            detection,
            blocking,
        }
    }
}

impl<'sc> ServiceConfig<'sc> for FloodManagementConfig {
    /// Returns the name of the flood management service.
    fn name() -> &'static str {
        "Flood Management"
    }

    /// Returns the port associated with the service, if any.
    fn port() -> Option<u16> {
        None
    }
}

/// Flood management service that integrates detection and blocking components.
///
/// This service coordinates flood detection and automatic mitigation
/// using IPTables or equivalent mechanisms.
pub struct FloodManagement;

impl<'s> ServiceHandle<'s> for FloodManagement {
    type Config = FloodManagementConfig;
    type Args = Arc<mpsc::Sender<CommsEvent>>;
    type Output = ();

    /// Starts the flood management service.
    ///
    /// This function initializes and runs both the detection and blocking subsystems.
    ///
    /// # Arguments
    ///
    /// * `node` - Reference to the local node context.
    /// * `config` - Configuration for the service.
    /// * `comms_channel` - Communication channel to send events.
    ///
    /// # Returns
    ///
    /// A result containing an empty output and a join handle to the service thread.
    fn run(
        node: &Node,
        config: &Self::Config,
        comms_channel: Self::Args,
    ) -> Result<(Self::Output, JoinHandle<()>), Box<dyn Error>> {
        // Run detection first, get flood events receiver
        let (detection_output, detection_handle) =
            FloodDetection::run(node, &config.detection, Arc::clone(&comms_channel))?;

        let (_unit, flood_event_rx) = detection_output;

        // Run blocking service, pass flood event receiver and comms sender
        let (blocking_output, blocking_handle) = FloodBlocking::run(
            node,
            &config.blocking,
            (flood_event_rx, comms_channel.as_ref().clone()),
        )?;

        // Spawn a thread to join both service handles
        let handle = thread::spawn(move || {
            let _ = detection_handle.join();
            let _ = blocking_handle.join();
        });

        Ok(((), handle))
    }
}
