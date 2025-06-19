use notify::event::ModifyKind;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use std::error::Error;
use std::path::Path;
use std::sync::{
    mpsc::{channel, Sender},
    Arc,
};

use std::thread::{self, JoinHandle};

use std::time::Duration;

use crate::services::comms::CommsEvent;
use crate::services::{ServiceConfig, ServiceHandle};

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct HoneypotConfig {
    pub directory: String,
}

impl<'ac> ServiceConfig<'ac> for HoneypotConfig {
    fn name() -> &'static str {
        "Honeypot"
    }
    fn port() -> Option<u16> {
        Some(50055)
    }
}

impl Default for HoneypotConfig {
    fn default() -> Self {
        HoneypotConfig {
            directory: "./honeypot".to_string(), // directory to watch
        }
    }
}

pub struct Honeypot;

impl Honeypot {
    /// Computes a delay before sending event based on its kind
    fn compute_ttl(event: &CommsEvent) -> i64 {
        2
    }

    fn watch_directory(
        ip: String,
        directory: String,
        event_tx: Arc<Sender<CommsEvent>>,
    ) -> Result<JoinHandle<()>, Box<dyn Error>> {
        let path = Path::new(&directory);
        if !path.exists() {
            return Err(format!("Watch directory does not exist: {}", directory).into()); 
        }
        if !path.is_dir() {
            return Err(format!("Watch path is not a directory: {}", directory).into()); 
        }
        let (tx, rx) = channel();

        let mut watcher = RecommendedWatcher::new(
            move |res| {
                let _ = tx.send(res);
            },
            Config::default(), 
        )
        .map_err(|e| format!("Failed to create file watcher: {}", e))?;

        watcher
            .watch(path, RecursiveMode::Recursive)
            .map_err(|e| format!("Failed to watch directory '{}': {}", directory, e))?;

        let handle = thread::spawn(move || {
            let mut _watcher = watcher; // Keep alive

            for res in rx {
                let event = match res {
                    Ok(event) => event,
                    Err(e) => {
                        Honeypot::log(format_args!("File watch error: {}", e)); 
                        continue;
                    }
                };
                
                if event.paths.is_empty() {
                    continue;
                }
                
                let kind = match &event.kind {
                    EventKind::Create(_) => "creation",
                    EventKind::Remove(_) => "deletion",
                    EventKind::Modify(ModifyKind::Data(_)) => "data modification",
                    EventKind::Modify(ModifyKind::Metadata(_)) => "metadata modification",
                    _ => "change",
                };
                
                let paths = event
                    .paths
                    .iter()
                    .map(|p| p.to_string_lossy().to_string()) 
                    .collect::<Vec<String>>()
                    .join(", ");
                
                let message = format!("Unauthorized {} of: {}", kind, paths);
                
                let event = CommsEvent::new::<Honeypot>(&ip, "Honeypot Event", &message, 2);

                let event_tx = Arc::clone(&event_tx);
                
                thread::spawn(move || {
                    let delay = Honeypot::compute_ttl(&event);
                    if let Err(e) = event_tx.send(event) {
                        Honeypot::log(format_args!("Failed to forward event: {}", e)); 
                    }
                });
            }
        });

        Ok(handle)
    }

    fn log(args: std::fmt::Arguments) {
        println!("[Honeypot] {}", args);
    }
}

impl<'ac> ServiceHandle<'ac> for Honeypot {
    type Config = HoneypotConfig;
    type Args = Arc<Sender<CommsEvent>>;
    type Output = ();

    fn run(
        node: &crate::node::Node,
        config: &HoneypotConfig,
        event_tx: Self::Args,
    ) -> Result<((), JoinHandle<()>), Box<dyn Error>> {
        let directory = config.directory.clone();

        let handle = Honeypot::watch_directory(
            node.running_config.ip.clone(), 
            directory, 
            event_tx,
        )?;

        Ok(((), handle))
    }
}
