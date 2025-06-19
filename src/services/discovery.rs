use super::{ServiceConfig, ServiceHandle};
use crate::node::{knowledge::NodeKnowledgeHandler, Node};
use base64;
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NodeAnnwnDetails {
    pub ip: String,
    pub name: String,
    pub signature: String,
}

impl Node {
    fn get_annwn_details(&self, secret_key: &[u8]) -> NodeAnnwnDetails {
        let ip = self.running_config.ip.to_owned();
        let name = self.init_config.name.to_owned();

        let message = format!("{}:{}", ip, name);
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret_key);
        let sig = hmac::sign(&key, message.as_bytes());

        NodeAnnwnDetails {
            ip,
            name,
            signature: base64::encode(sig.as_ref()),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    pub secret_key: String,  // plaintext in config
}

impl DiscoveryConfig {
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.secret_key.as_bytes().to_vec()
    }
}

impl<'ac> ServiceConfig<'ac> for DiscoveryConfig {
    fn name() -> &'static str {
        "Discovery"
    }
    fn port() -> Option<u16> {
        Some(4321)
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            secret_key: "your-32-byte-shared-secret-123!".to_string(),
        }
    }
}

pub fn get_multicast_addr() -> SocketAddr {
    format!("239.0.0.1:{}", DiscoveryConfig::port().unwrap())
        .parse()
        .expect("Invalid multicast address")
}

pub struct Discovery;

impl Discovery {
    fn announce(details: &NodeAnnwnDetails) -> Result<(), Box<dyn Error>> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_multicast_loop_v4(true)?;
        socket.set_multicast_ttl_v4(1)?;
        let addr = get_multicast_addr();
        let message = serde_json::to_string(details)?;
        socket.send_to(message.as_bytes(), addr)?;
        Ok(())
    }

    fn verify_signature(details: &NodeAnnwnDetails, secret_key: &[u8]) -> bool {
        let message = format!("{}:{}", details.ip, details.name);
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret_key);
        let expected = hmac::sign(&key, message.as_bytes());

        match base64::decode(&details.signature) {
            Ok(sig) => hmac::verify(&key, message.as_bytes(), &sig).is_ok()
                && sig == expected.as_ref(),
            Err(_) => false,
        }
    }

    /// Blocking listen loop - does NOT spawn a thread.
    fn listen(
        node_knowledge_handler: NodeKnowledgeHandler,
        secret_key: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let socket = UdpSocket::bind(("0.0.0.0", DiscoveryConfig::port().unwrap()))?;
        socket.set_nonblocking(true)?;
        socket.join_multicast_v4(&Ipv4Addr::new(239, 0, 0, 1), &Ipv4Addr::UNSPECIFIED)?;

        loop {
            let mut buf = [0u8; 1024];
            match socket.recv_from(&mut buf) {
                Ok((size, _src)) => {
                    if let Ok(text) = std::str::from_utf8(&buf[..size]) {
                        if let Ok(details) = serde_json::from_str::<NodeAnnwnDetails>(text) {
                            // Validate HMAC first
                            if !Discovery::verify_signature(&details, secret_key) {
                                <Discovery as ServiceHandle>::log(format_args!(
                                    "Rejected node with invalid HMAC: {:?}",
                                    details
                                ));
                                continue;
                            }
                            if let Err(e) = Discovery::persist_discovered_node(
                                &details,
                                &node_knowledge_handler,
                            ) {
                                <Discovery as ServiceHandle>::log(format_args!(
                                    "Failed to persist node: {}",
                                    e
                                ));
                            } else {
                                <Discovery as ServiceHandle>::log(format_args!(
                                    "Discovered or updated node: {:#?}",
                                    details
                                ));
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(200));
                }
                Err(e) => {
                    <Discovery as ServiceHandle>::log(format_args!("UDP recv_from error: {}", e));
                    thread::sleep(Duration::from_millis(200));
                }
            }
        }
    }
}

trait PersistDiscovery {
    fn table_schema() -> &'static str;

    fn persist_discovered_node(
        details: &NodeAnnwnDetails,
        handler: &NodeKnowledgeHandler,
    ) -> Result<(), Box<dyn Error>>;
}

impl PersistDiscovery for Discovery {
    fn table_schema() -> &'static str {
        r#"
            CREATE TABLE IF NOT EXISTS known_nodes (
                ip TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                last_seen INTEGER NOT NULL
            );
        "#
    }

    fn persist_discovered_node(
        details: &NodeAnnwnDetails,
        handler: &NodeKnowledgeHandler,
    ) -> Result<(), Box<dyn Error>> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() as i64;

        let sql = "INSERT INTO known_nodes (ip, name, last_seen) VALUES (?, ?, ?)
                   ON CONFLICT(ip) DO UPDATE SET name = excluded.name, last_seen = excluded.last_seen";

        handler.execute_sql_params(sql, [&details.ip, &details.name, &timestamp.to_string()])?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct DiscoveredNodesHandler {
    handler: NodeKnowledgeHandler,
}

impl DiscoveredNodesHandler {
    pub fn get_known_nodes(&self) -> Vec<NodeAnnwnDetails> {
        let mut known_nodes = Vec::new();
        let query = "SELECT ip, name FROM known_nodes";

        match self.handler.query_sql(query) {
            Ok(rows) => {
                for row in rows {
                    if let (Some(ip), Some(name)) = (row.get("ip"), row.get("name")) {
                        known_nodes.push(NodeAnnwnDetails {
                            ip: ip.to_owned(),
                            name: name.to_owned(),
                            signature: String::new(), // HMAC not stored
                        });
                    }
                }
            }
            Err(e) => eprintln!("Failed to query known nodes: {}", e),
        }
        known_nodes
    }

    pub fn ip_in_nodes(&self, ip: &str) -> bool {
        let query = "SELECT 1 FROM known_nodes WHERE ip = ?";
        match self.handler.query_sql_params(query, &[&ip]) {
            Ok(rows) => !rows.is_empty(),
            Err(e) => {
                eprintln!("Failed to query IP presence: {}", e);
                false
            }
        }
    }

    pub fn remove_from_known_nodes(&self, ip: &str) {
        let query = "DELETE FROM known_nodes WHERE ip = ?";
        if let Err(e) = self.handler.execute_sql_params(query, [&ip]) {
            eprintln!("Failed to remove node with IP {}: {}", ip, e);
        }
    }
}

pub struct DiscoveryArgs;

impl<'ac> ServiceHandle<'ac> for Discovery {
    type Config = DiscoveryConfig;
    type Args = DiscoveryArgs;
    type Output = (DiscoveredNodesHandler, Vec<u8>);

    fn run(
        node: &Node,
        config: &DiscoveryConfig,
        _args: DiscoveryArgs,
    ) -> Result<(Self::Output, JoinHandle<()>), Box<dyn Error>> {
        node.logger
            .execute_sql(<Discovery as PersistDiscovery>::table_schema())?;

        let key_bytes = config.secret_key_bytes();
        let details = node.get_annwn_details(&key_bytes);
        let handler = node.logger.clone();

        // Spawn listener thread
        let listen_key = key_bytes.clone();
        let listen_handler = handler.clone();
        thread::spawn(move || {
            if let Err(e) = Discovery::listen(listen_handler, &listen_key) {
                <Discovery as ServiceHandle>::log(format_args!("Listener thread exited with error: {}", e));
            }
        });

        // Spawn announcer thread
        let announcement = details.clone();
        let announcer = thread::spawn(move || loop {
            if let Err(e) = Discovery::announce(&announcement) {
                <Discovery as ServiceHandle>::log(format_args!("Announcement error: {}", e));
            }
            thread::sleep(Duration::from_secs(10));
        });

        Ok((
            (DiscoveredNodesHandler {
                handler: node.logger.clone(),
            }, config.secret_key.clone().into()) ,
            announcer,
        ))
    }
}

/// Loads the DiscoveryConfig from the TOML config file path
pub fn load_discovery_config_from_file(path: &str) -> Result<DiscoveryConfig, Box<dyn Error>> {
    let contents = fs::read_to_string(path)?;
    let toml_value: toml::Value = toml::from_str(&contents)?;

    let discovery_table = toml_value
        .get("Discovery")
        .ok_or("Missing [Discovery] section in config")?;

    let config: DiscoveryConfig = discovery_table.clone().try_into()?;

    Ok(config)
}
