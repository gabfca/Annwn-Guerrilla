use chrono::Utc;
use serde::{Deserialize, Serialize};

use std::collections::HashSet;
use std::error::Error;
use std::io::Write;
use std::io::{BufRead, BufReader};

use std::net::{TcpListener, TcpStream};

use std::sync::mpsc::{self, Sender};

use std::sync::{Arc, Mutex};

use std::thread::{self, JoinHandle};

use std::time::Duration;

use base64;

use once_cell::sync::Lazy;

use ring::hmac;

use sha2::{Digest, Sha256};

use super::discovery::DiscoveredNodesHandler;
use super::{ServiceConfig, ServiceHandle};

use crate::node::knowledge::NodeKnowledgeHandler;
use crate::node::Node;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommsEvent {
    pub source_node_ip: String,
    pub source_service: String,
    pub message_title: String,
    pub message_contents: String,
    pub propagation_ttl: i64,
    pub created_at_timestamp: String,

    #[serde(skip)]

    #[serde(default)]

    pub immediate_sender_ip: Option<String>,
}

impl<'ce> CommsEvent {
    pub fn new<S: ServiceHandle<'ce>>(
        source_ip: &str,
        title: &str,
        contents: &str,
        propagation_tl: i64,
    ) -> Self
    where
        S::Config: ServiceConfig<'ce>,
    {
        CommsEvent {
            source_node_ip: source_ip.to_owned(), 
            source_service: S::Config::name().to_string(), 
            message_title: title.to_owned(), 
            message_contents: contents.to_owned(), 
            propagation_ttl: propagation_tl, 
            created_at_timestamp: Utc::now().to_rfc2822(), 
            immediate_sender_ip: None,
        }
    }

    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.source_node_ip);
        hasher.update(&self.source_service);
        hasher.update(&self.message_title);
        hasher.update(&self.message_contents);
        hasher.update(&self.created_at_timestamp);
        format!("{:x}", hasher.finalize()) 
    }

    pub fn encode(&self, secret_key: &[u8]) -> Result<String, Box<dyn Error>> {
        let json = serde_json::to_string(self)?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret_key);
        let sig = hmac::sign(&key, json.as_bytes()); 
        let sig_b64 = base64::encode(sig.as_ref());

        #[derive(Serialize)]

        struct SignedMessage<'a> {
            signature: &'a str,
            payload: &'a str,
        }

        let wrapped = SignedMessage {
            signature: &sig_b64,
            payload: &json,
        };
        Ok(serde_json::to_string(&wrapped)?)
    }

    pub fn decode(signed_message: &str, secret_key: &[u8]) -> Result<Self, Box<dyn Error>> {
        #[derive(Deserialize)]

        struct SignedMessage {
            signature: String,
            payload: String,
        }
        let wrapped: SignedMessage = serde_json::from_str(signed_message)?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret_key);
        let sig_bytes = base64::decode(&wrapped.signature)?;
        hmac::verify(&key, wrapped.payload.as_bytes(), &sig_bytes)
            .map_err(|_| "Invalid signature")?;

        let event: CommsEvent = serde_json::from_str(&wrapped.payload)?;
        Ok(event)
    }
}

static EVENT_HASHES: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| Mutex::new(HashSet::new()) );

#[derive(Clone, Deserialize, Serialize)]

pub struct CommsConfig;

impl<'ac> ServiceConfig<'ac> for CommsConfig {
    fn name() -> &'static str { "Comms" }
    fn port() -> Option<u16> { Some(61616) }
}

impl Default for CommsConfig {
    fn default() -> Self { Self {} }
}

pub struct Comms;

impl Comms {
    fn table_schema() -> &'static str {
        r#"
        CREATE TABLE IF NOT EXISTS comms_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_node_ip TEXT NOT NULL,
            source_service TEXT NOT NULL,
            message_title TEXT NOT NULL,
            message_contents TEXT NOT NULL,
            propagation_ttl INTEGER NOT NULL,
            created_at_timestamp TEXT NOT NULL,
            received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        "#
    }
    pub fn persist_event(
        event: &CommsEvent,
        handler: &NodeKnowledgeHandler,
    ) -> Result<(), Box<dyn Error>> {
        handler.execute_sql("PRAGMA foreign_keys = ON;")?;

        let sql = "
            INSERT INTO comms_events (
                source_node_ip, source_service, message_title, message_contents, 
                propagation_ttl, created_at_timestamp
            ) VALUES (?, ?, ?, ?, ?, ?)
        ";

        handler.execute_sql_params(
            sql,
            &[
                &event.source_node_ip,
                &event.source_service,
                &event.message_title,
                &event.message_contents,
                &event.propagation_ttl.to_string(), 
                &event.created_at_timestamp,
            ],
        )?;

        Ok(())
    }

    fn handle_client(
        stream: TcpStream,
        internal_knowledge: Arc<NodeKnowledgeHandler>,
        known_nodes_handler: Arc<DiscoveredNodesHandler>,
        tx: Sender<CommsEvent>,
        secret_key: Arc<Vec<u8>>,
    ) -> Result<(), Box<dyn Error>> {
        let peer_ip = stream.peer_addr()?.ip().to_string();
        let reader = BufReader::new(stream);

        for line_result in reader.lines() {
            let line = line_result?;

            if line.trim().is_empty() {
                continue;
            }
            let event = match CommsEvent::decode(&line, &secret_key) {
                Ok(ev) => ev,
                Err(_) => {
                    Self::log(format_args!("Rejected message with invalid signature from {}", peer_ip)); 
                    continue;
                }
            };
            if !known_nodes_handler.ip_in_nodes(&event.source_node_ip) {
                return Err(format!("Rejected message from unknown IP: {}", event.source_node_ip).into()) 
            }
            let event_hash = event.hash();

            {
                let mut seen = EVENT_HASHES.lock().unwrap();

                if seen.contains(&event_hash) {
                    Self::log(format_args!("Duplicate event '{}' detected, skipping.", event.message_title)); 
                    continue;
                }
                seen.insert(event_hash);
            }
            let mut event = event;
            event.immediate_sender_ip = Some(peer_ip.clone());

            let prop_ttl = event.propagation_ttl;

            if prop_ttl > 0 {
                Self::persist_event(&event, &internal_knowledge)?;
                event.propagation_ttl -= 1;
                if let Err(e) = tx.send(event.clone()) {
                    Self::log(format_args!("Failed to queue message for propagation: {}.", e)); 
                }
            }
            Self::log(format_args!("'{}' | FROM: {} (original sender {}) | TTL {} | SERVICE {}.", 
                                   event.message_title, 
                                   peer_ip, 
                                   event.source_node_ip, 
                                   prop_ttl, 
                                   event.source_service)); 
        }
        Ok(())
    }

    pub fn start_listener(
        internal_knowledge: NodeKnowledgeHandler,
        discovered_nodes_handler: DiscoveredNodesHandler,
        tx: Sender<CommsEvent>,
        secret_key: Arc<Vec<u8>>,
    ) -> Result<JoinHandle<()>, Box<dyn Error>> {
        let listener = TcpListener::bind(("0.0.0.0", CommsConfig::port().unwrap()))?;

        listener.set_nonblocking(true)?;
        let internal_knowledge = Arc::new(internal_knowledge);
        let discovered_nodes = Arc::new(discovered_nodes_handler);
        let secret_key = secret_key.clone();

        let handle = thread::spawn(move || {
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let handler = Arc::clone(&internal_knowledge);
                        let discovered = Arc::clone(&discovered_nodes);
                        let tx = tx.clone();
                        let secret_key = secret_key.clone();

                        thread::spawn(move || {
                            if let Err(e) = Comms::handle_client(stream, handler, discovered, tx, secret_key) {
                                Comms::log(format_args!("Client handling error: {}", e)); 
                            }
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(100)); 
                    }
                    Err(e) => {
                        Comms::log(format_args!("Listener error: {}.", e)); 
                        thread::sleep(Duration::from_secs(1)); 
                    }
                }
            }
        });

        Ok(handle)
    }

    fn start_forwarding_loop(
        rx: mpsc::Receiver<CommsEvent>,
        forward_tx: Sender<CommsEvent>,
        known_nodes_handler: DiscoveredNodesHandler,
        our_ip: String,
        secret_key: Arc<Vec<u8>>,
    ) -> JoinHandle<()> {
        thread::spawn(move || {
            for event in rx {
                Self::propagate_event_to_known_nodes(
                    &event,
                    &known_nodes_handler,
                    &forward_tx,
                    &our_ip,
                    &secret_key,
                );
            }
        })
    }
    fn propagate_event_to_known_nodes(
        event: &CommsEvent,
        known_nodes_handler: &DiscoveredNodesHandler,
        forward_tx: &Sender<CommsEvent>,
        our_ip: &str,
        secret_key: &Arc<Vec<u8>>,
    ) {
        for target in known_nodes_handler.get_known_nodes() 
        {
            let mut event = event.clone();

            let original_prop_ttl = event.propagation_ttl;

            if let Some(ref immediate_ip) = event.immediate_sender_ip {
                if &target.ip == immediate_ip { continue }
            }
            let addr = format!("{}:{}", target.ip, CommsConfig::port().unwrap());

            match TcpStream::connect(&addr) {
                Ok(mut stream) => {
                    if let Ok(encoded) = event.encode(&secret_key) {
                        if let Err(e) = writeln!(stream, "{}", encoded) {
                            Comms::log(format_args!("Failed to send to {}: {}.", target.ip, e)); 
                        }
                    }
                }
                Err(_) => {
                    known_nodes_handler.remove_from_known_nodes(&target.ip);
                    let failure_comm = CommsEvent::new::<Comms>(
                        our_ip,
                        "Forgot Node",
                        &format!("Was unable to send comms to node at IP {}; I have dropped it.", target.ip),
                        1,
                    );

                    if let Err(e) = forward_tx.send(failure_comm) {
                        Comms::log(format_args!("Failed to requeue comms failure event: {}.", e)); 
                    }
                }
            }
            event.propagation_ttl = original_prop_ttl;
        }
    }
    fn start_wellness_thread(forward_tx: Sender<CommsEvent>, our_ip: String) -> JoinHandle<()> {
        thread::spawn(move || {
            let wellness_interval = Duration::from_secs(30);
            loop {
                thread::sleep(wellness_interval);
                
                let wellness_event = CommsEvent::new::<Comms>(
                    &our_ip,
                    "Wellness Check",
                    "This is an automated periodic wellness check from the node.",
                    -1,
                );

                if let Err(e) = forward_tx.send(wellness_event) {
                    Comms::log(format_args!("Failed to enqueue wellness check event: {}.", e)); 
                }
            }
        })
    }
    fn log(args: std::fmt::Arguments) {
        println!("[Comms] {}", args);
    }
}

impl<'ac> ServiceHandle<'ac> for Comms {
    type Config = CommsConfig;
    type Args = (&'ac DiscoveredNodesHandler, Arc<Vec<u8>>);
    type Output = Sender<CommsEvent>;

    fn run(
        node: &Node,
        _config: &CommsConfig,
        args: Self::Args,
    ) -> Result<(Self::Output, JoinHandle<()>), Box<dyn Error>> {
        node.logger.execute_sql(Self::table_schema())?;

        let (tx, rx) = mpsc::channel::<CommsEvent>();
        let our_ip = node.running_config.ip.clone();

        let (discovered_nodes_handler, secret_key) = args;

        let listener_handle = Self::start_listener(
            node.logger.clone(), 
            discovered_nodes_handler.clone(), 
            tx.clone(), 
            secret_key.clone()
        )?;

        let forward_handle = Self::start_forwarding_loop(
            rx, 
            tx.clone(), 
            discovered_nodes_handler.clone(), 
            our_ip.clone(), 
            secret_key.clone()
        );

        let wellness_handle = Self::start_wellness_thread(tx.clone(), our_ip);

        let combined_handle = thread::spawn(move || {
            listener_handle.join().ok();
            forward_handle.join().ok();
            wellness_handle.join().ok();
        });

        Ok((tx, combined_handle))
    }
}
