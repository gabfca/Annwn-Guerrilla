//! Flood detection service implementation.
//!
//! This module provides functionality for detecting network flood attacks by
//! monitoring packet traffic patterns and analyzing source IP behavior.

use pcap::{Capture, Device};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    error::Error,
    net::IpAddr,
    sync::{mpsc, Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use crate::{
    node::Node,
    services::{comms::CommsEvent, ServiceConfig, ServiceHandle},
};

/// Event generated when a potential flood is detected
#[derive(Debug, Clone)]
pub struct FloodDetectionEvent {
    /// Source IP address of the suspected flood traffic
    pub source_ip: IpAddr,
    /// Destination port being targeted
    pub destination_port: u16,
    /// Time when the detection occurred
    pub timestamp: Instant,
}

/// Parses a network packet to extract source IP and destination port
///
/// # Arguments
///
/// * `packet_data` - Raw packet data bytes
///
/// # Returns
///
/// Option containing tuple of (source_ip, destination_port) if parsing succeeds
fn parse_packet(packet_data: &[u8]) -> Option<(IpAddr, u16)> {
    if packet_data.len() < 34 {
        return None;
    }
    if packet_data[12] == 0x08 && packet_data[13] == 0x00 {
        let src_ip = IpAddr::from([
            packet_data[26],
            packet_data[27],
            packet_data[28],
            packet_data[29],
        ]);
        let protocol = packet_data[23];
        let ihl = (packet_data[14] & 0x0F) as usize * 4;
        let transport_header_start = 14 + ihl;
        if (protocol == 6 || protocol == 17) && packet_data.len() >= transport_header_start + 4 {
            let dst_port = u16::from_be_bytes([
                packet_data[transport_header_start + 2],
                packet_data[transport_header_start + 3],
            ]);
            return Some((src_ip, dst_port));
        }
    }
    None
}

/// Configuration for flood detection service
#[derive(Clone, Deserialize, Serialize)]
pub struct FloodDetectionConfig {
    /// Ports to monitor for flood activity
    pub monitored_ports: Vec<u16>,
    /// Packet count threshold to trigger flood detection
    pub packet_threshold: usize,
    /// Time window for evaluating packet counts
    pub detection_interval: Duration,
    /// Minimum time between alerts for the same source
    pub alert_cooldown: Duration,
    /// Entropy threshold for detecting IP diversity attacks
    pub entropy_threshold: f64,
}

/// Trait defining sensitivity presets for flood detection
pub trait Sensitivity {
    /// Creates a low sensitivity configuration
    fn low(ports: Vec<u16>) -> Self;
    /// Creates a medium sensitivity configuration
    fn medium(ports: Vec<u16>) -> Self;
    /// Creates a high sensitivity configuration
    fn high(ports: Vec<u16>) -> Self;
}

impl Sensitivity for FloodDetectionConfig {
    fn low(ports: Vec<u16>) -> Self {
        Self {
            monitored_ports: ports,
            packet_threshold: 5000,
            detection_interval: Duration::from_secs(1),
            alert_cooldown: Duration::from_secs(10),
            entropy_threshold: 4.0,
        }
    }

    fn medium(ports: Vec<u16>) -> Self {
        Self {
            monitored_ports: ports,
            packet_threshold: 1000,
            detection_interval: Duration::from_secs(2),
            alert_cooldown: Duration::from_secs(10),
            entropy_threshold: 3.0,
        }
    }

    fn high(ports: Vec<u16>) -> Self {
        Self {
            monitored_ports: ports,
            packet_threshold: 200,
            detection_interval: Duration::from_secs(3),
            alert_cooldown: Duration::from_secs(10),
            entropy_threshold: 2.0,
        }
    }
}

impl Default for FloodDetectionConfig {
    /// Creates default medium sensitivity configuration monitoring common ports
    fn default() -> Self {
        Sensitivity::medium(vec![22, 80, 8080, 443, 7879, 61616])
    }
}

impl<'sc> ServiceConfig<'sc> for FloodDetectionConfig {
    /// Returns the service name
    fn name() -> &'static str {
        "Flood Detection"
    }

    /// Returns None since this service doesn't use a specific port
    fn port() -> Option<u16> {
        None
    }
}

/// Flood detection service handler
pub struct FloodDetection;

impl<'s> ServiceHandle<'s> for FloodDetection {
    type Config = FloodDetectionConfig;
    type Args = Arc<mpsc::Sender<CommsEvent>>;
    type Output = ((), mpsc::Receiver<FloodDetectionEvent>);

    /// Runs the flood detection service
    ///
    /// # Arguments
    ///
    /// * `node` - Reference to the node
    /// * `config` - Service configuration
    /// * `comms_channel` - Channel for sending communication events
    ///
    /// # Returns
    ///
    /// Result containing:
    /// - Tuple of (empty output, flood detection event receiver)
    /// - JoinHandle for the service thread
    ///
    /// # Behavior
    ///
    /// 1. Captures network packets using pcap
    /// 2. Analyzes traffic patterns using multiple detection methods:
    ///    - Packet count thresholds
    ///    - Source IP diversity (entropy)
    ///    - Bursty traffic patterns (timing variance)
    /// 3. Generates events when potential floods are detected
    fn run(
        node: &Node,
        config: &Self::Config,
        comms_channel: Self::Args,
    ) -> Result<(Self::Output, JoinHandle<()>), Box<dyn Error>> {
        let node_ip = node.running_config.ip.clone();
        let config = config.clone();
        let (event_tx, event_rx) = mpsc::sync_channel::<FloodDetectionEvent>(100);
        let bucket_count = 10;
        let bucket_duration = config.detection_interval / bucket_count as u32;

        let handle = thread::spawn(move || {
            let device = match Device::lookup() {
                Ok(Some(d)) => d,
                _ => {
                    FloodDetection::log(format_args!("Device lookup failed"));
                    return;
                }
            };

            let mut capture = match Capture::from_device(device)
                .and_then(|c| Ok(c.promisc(true).snaplen(5000)))
                .and_then(|c| c.open())
                .map(|mut c| {
                    c.filter("ip and (tcp or udp)", true).unwrap();
                    c
                }) {
                Ok(c) => c,
                Err(e) => {
                    FloodDetection::log(format_args!("Failed to open capture: {}", e));
                    return;
                }
            };

            let traffic_counts = Arc::new(Mutex::new(HashMap::<(IpAddr, u16), VecDeque<usize>>::new()));
            let port_ip_sets = Arc::new(Mutex::new(HashMap::<u16, HashSet<IpAddr>>::new()));
            let last_alerts = Arc::new(Mutex::new(HashMap::<(IpAddr, u16), Instant>::new()));
            let ip_packet_times = Arc::new(Mutex::new(HashMap::<IpAddr, Vec<Instant>>::new()));

            /// Calculates entropy of IP addresses in a set
            fn calculate_entropy(ip_set: &HashSet<IpAddr>) -> f64 {
                use std::f64::consts::LN_2;
                let n = ip_set.len() as f64;
                if n == 0.0 { return 0.0; }
                (n.ln()) / LN_2
            }

            /// Maintains bucket count within configured limits
            fn cleanup_old_buckets(buckets: &mut VecDeque<usize>, max_buckets: usize) {
                while buckets.len() > max_buckets {
                    buckets.pop_front();
                }
            }

            let mut last_bucket_time = Instant::now();

            while let Ok(packet) = capture.next_packet() {
                let now = Instant::now();

                if now.duration_since(last_bucket_time) >= bucket_duration {
                    let mut counts = traffic_counts.lock().unwrap();
                    for buckets in counts.values_mut() {
                        buckets.push_back(0);
                        cleanup_old_buckets(buckets, bucket_count);
                    }
                    last_bucket_time = now;

                    let mut ip_sets = port_ip_sets.lock().unwrap();
                    ip_sets.clear();
                }

                if let Some((source_ip, destination_port)) = parse_packet(packet.data) {
                    if !config.monitored_ports.contains(&destination_port) {
                        continue;
                    }

                    let mut counts = traffic_counts.lock().unwrap();
                    let buckets = counts.entry((source_ip, destination_port)).or_insert_with(|| {
                        let mut dq = VecDeque::with_capacity(bucket_count);
                        dq.resize(bucket_count, 0);
                        dq
                    });
                    if let Some(last) = buckets.back_mut() {
                        *last += 1;
                    }

                    let mut ip_sets = port_ip_sets.lock().unwrap();
                    let ip_set = ip_sets.entry(destination_port).or_insert_with(HashSet::new);
                    ip_set.insert(source_ip);

                    {
                        let mut ip_times = ip_packet_times.lock().unwrap();
                        let times = ip_times.entry(source_ip).or_insert_with(Vec::new);
                        times.push(now);
                        if times.len() > 20 {
                            times.drain(0..times.len() - 20);
                        }
                    }

                    let total_packets: usize = buckets.iter().sum();

                    if total_packets > config.packet_threshold {
                        let mut last_alerts_map = last_alerts.lock().unwrap();
                        if let Some(last_alert_time) = last_alerts_map.get(&(source_ip, destination_port)) {
                            if now.duration_since(*last_alert_time) < config.alert_cooldown {
                                continue;
                            }
                        }
                        last_alerts_map.insert((source_ip, destination_port), now);
                        FloodDetection::log(format_args!(
                            "Potential flood detected from {} on port {} (count {})",
                            source_ip, destination_port, total_packets
                        ));
                        let event = CommsEvent::new::<FloodDetection>(
                            &node_ip,
                            "Potential Flood",
                            &format!("Port {} subjected to unusual traffic from IP {}.", destination_port, source_ip),
                            2,
                        );
                        let _ = comms_channel.send(event);
                        let _ = event_tx.send(FloodDetectionEvent {
                            source_ip,
                            destination_port,
                            timestamp: now,
                        });
                        continue;
                    }

                    let entropy = calculate_entropy(ip_set);
                    if entropy > config.entropy_threshold {
                        FloodDetection::log(format_args!(
                            "High IP diversity detected on port {}: entropy {:.2}",
                            destination_port, entropy
                        ));
                        let event = CommsEvent::new::<FloodDetection>(
                            &node_ip,
                            "Potential Flood (High IP Diversity)",
                            &format!(
                                "Port {} subjected to high source IP diversity (entropy {:.2}) indicating possible IP shuffling attack.",
                                destination_port, entropy
                            ),
                            2,
                        );
                        let _ = comms_channel.send(event);
                        for ip in ip_set.iter().take(10) {
                            let _ = event_tx.send(FloodDetectionEvent {
                                source_ip: *ip,
                                destination_port,
                                timestamp: now,
                            });
                        }
                    }

                    let mut alert_on_behavior = false;
                    {
                        let ip_times = ip_packet_times.lock().unwrap();
                        if let Some(times) = ip_times.get(&source_ip) {
                            if times.len() >= 5 {
                                let intervals: Vec<_> = times.windows(2).map(|w| (w[1] - w[0]).as_millis() as f64).collect();
                                let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
                                let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
                                if variance < 10.0 {
                                    alert_on_behavior = true;
                                }
                            }
                        }
                    }
                    if alert_on_behavior
                     {
                        let mut last_alerts_map = last_alerts.lock().unwrap();
                        if let Some(last_alert_time) = last_alerts_map.get(&(source_ip, destination_port)) {
                    
                            if now.duration_since(*last_alert_time) >= config.alert_cooldown {
                                FloodDetection::log(format_args!(
                                    "Bursty behavior detected from {} on port {} (low timing variance)",
                                    source_ip, destination_port
                                ));
                    
                    
                                let event = CommsEvent::new::<FloodDetection>(
                                    &node_ip,
                                    "Potential Flood (Bursty Behavior)",
                                    &format!("Port {} subjected to bursty traffic from IP {} (low timing variance).", destination_port, source_ip),
                                    2,
                                );
                                let _ = comms_channel.send(event);
                                last_alerts_map.insert((source_ip, destination_port), now);
                                let _ = event_tx.send(FloodDetectionEvent {
                                    source_ip,
                                    destination_port,
                                    timestamp: now,
                                });
                            }
                        }
                    }
                }
            }
        });

        Ok((((), event_rx), handle))
    }
}