//! Flood blocking service implementation.
//!
//! This module provides functionality for blocking and unblocking IP addresses
//! suspected of flood attacks using iptables.

use serde::{Deserialize, Serialize};
use std::{
    default, error::Error, net::IpAddr, process::Command, 
    sync::mpsc::{Receiver, Sender}, thread::{self, JoinHandle}, 
    time::{Duration, Instant}
};

use crate::{
    node::Node,
    services::flood_management::detection::FloodDetectionEvent,
    services::{comms::CommsEvent, ServiceConfig, ServiceHandle},
};

/// Configuration for the flood blocking service.
#[derive(Clone, Deserialize, Serialize)]
pub struct FloodBlockingConfig {
    /// Duration for which an IP address will remain blocked
    pub block_duration: Duration,
    /// iptables chain where blocking rules will be added
    pub iptables_chain: String,
}

impl Default for FloodBlockingConfig {
    /// Creates default flood blocking configuration:
    /// - block_duration: 5 minutes
    /// - iptables_chain: "INPUT"
    fn default() -> Self {
        Self {
            block_duration: Duration::from_secs(5 * 60),
            iptables_chain: "INPUT".to_string(), 
        }
    }
}

impl FloodBlockingConfig {
    /// Computes the Time-To-Live (TTL) for flood blocking messages.
    ///
    /// The TTL is calculated based on the block duration, with a maximum of 10 hops.
    fn compute_ttl(&self) -> i64 {
        let secs = self.block_duration.as_secs();
        let ttl = (secs / 30) as i64;
        std::cmp::min(ttl, 10)
    }
}

impl<'sc> ServiceConfig<'sc> for FloodBlockingConfig {
    /// Returns the service name
    fn name() -> &'static str {
        "Flood Blocking"
    }

    /// Returns the service port (None for this service)
    fn port() -> Option<u16> {
        None
    }
}

/// Flood blocking service handler.
pub struct FloodBlocking;

impl<'s> ServiceHandle<'s> for FloodBlocking {
    type Config = FloodBlockingConfig;
    type Args = (Receiver<FloodDetectionEvent>, Sender<CommsEvent>);
    type Output = ();

    /// Runs the flood blocking service.
    ///
    /// # Arguments
    ///
    /// * `node` - Reference to the node
    /// * `config` - Service configuration
    /// * `args` - Tuple containing:
    ///   - Receiver for flood detection events
    ///   - Sender for communication events
    ///
    /// # Returns
    ///
    /// A Result containing:
    /// - Empty output tuple
    /// - JoinHandle for the service thread
    ///
    /// # Behavior
    ///
    /// 1. Maintains a list of blocked IPs and their unblock times
    /// 2. Processes flood detection events to block new attackers
    /// 3. Automatically unblocks IPs when their block duration expires
    /// 4. Sends communication events for block/unblock actions
    fn run(
        node: &Node,
        config: &Self::Config,
        args: Self::Args,
    ) -> Result<(Self::Output, JoinHandle<()>), Box<dyn Error>> {
        let (rx, comms_tx) = args;
        let config = config.clone();
        let our_ip = node.running_config.ip.clone();

        let handle = thread::spawn(move || {
            let mut blocked_ips = std::collections::HashMap::<IpAddr, Instant>::new();

            loop {
                let now = Instant::now();

                // Unblock and notify when block expires
                blocked_ips.retain(|ip, &mut unblock_time| {
                    if now >= unblock_time {
                        match unblock_ip(*ip, &config.iptables_chain) {
                            Ok(_) => {
                                println!("Unblocked IP: {}", ip);

                                let msg = format!("Unblocked IP {} after flood block", ip);
                                let ttl = config.compute_ttl() / 2;

                                let comms_event = CommsEvent::new::<FloodBlocking>(
                                    &our_ip,
                                    "Unblocked IP",
                                    &msg,
                                    ttl,
                                );

                                if let Err(e) = comms_tx.send(comms_event) {
                                    eprintln!("Failed to send unblock comms event: {}", e);
                                }
                            }
                            Err(e) => {
                                eprintln!("Failed to unblock IP {}: {}", ip, e);
                            }
                        }
                        false
                    } else {
                        true
                    }
                });

                // Handle flood detection events
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(event) => {
                        let ip = event.source_ip;
                        
                        // Skip blocking if it's our own IP
                        if ip.to_string() == our_ip {
                            println!("Ignoring flood event from own IP: {}", ip);
                            continue;
                        }

                        let newly_blocked = !blocked_ips.contains_key(&ip);

                        if newly_blocked {
                            // Block IP and set unblock time only if not already blocked
                            if let Err(e) = block_ip(ip, &config.iptables_chain) {
                                eprintln!("Failed to block IP {}: {}", ip, e);
                            } else {
                                println!("Blocked IP: {}", ip);
                            }

                            blocked_ips.insert(ip, Instant::now() + config.block_duration);

                            // Send a comms event on new block
                            let msg = format!("Blocked IP {} for suspected flood attack", ip);
                            let ttl = config.compute_ttl();

                            let comms_event =
                                CommsEvent::new::<FloodBlocking>(&our_ip, "Blocked IP", &msg, ttl);

                            if let Err(e) = comms_tx.send(comms_event) {
                                eprintln!("Failed to send comms event: {}", e);
                            }
                        } else {
                            println!("Received flood event from already blocked IP: {}", ip);
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // No events received, continue loop
                    }
                    Err(e) => {
                        eprintln!("Blocking service channel error: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(((), handle))
    }
}

/// Blocks an IP address using iptables.
///
/// # Arguments
///
/// * `ip` - IP address to block
/// * `chain` - iptables chain to add the block rule to
///
/// # Returns
///
/// Result indicating success or failure
fn block_ip(ip: IpAddr, chain: &str) -> Result<(), Box<dyn Error>> {
    let ip_str = ip.to_string();
    let status = Command::new("iptables")
        .args(&["-I", chain, "-s", &ip_str, "-j", "DROP"])
        .status()?;

    if !status.success() {
        return Err(format!("iptables block command failed with status {:?}", status).into());
    }
    Ok(())
}

/// Unblocks an IP address using iptables.
///
/// # Arguments
///
/// * `ip` - IP address to unblock
/// * `chain` - iptables chain where the block rule exists
///
/// # Returns
///
/// Result indicating success or failure
fn unblock_ip(ip: IpAddr, chain: &str) -> Result<(), Box<dyn Error>> {
    let ip_str = ip.to_string();
    println!("Running iptables unblock for IP: {}", ip_str);
    let status = Command::new("iptables")
        .args(&["-D", chain, "-s", &ip_str, "-j", "DROP"])
        .status()?;

    if !status.success() {
        return Err(format!("iptables unblock command failed with status {:?}", status).into());
    }
    Ok(())
}