pub mod comms;
pub mod dashboard;
pub mod discovery;
pub mod flood_management;
pub mod honeypot;

use serde::{Deserialize, Serialize};

use crate::node::Node;
use std::{
    error::Error,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread::JoinHandle,
    fs,
};

pub trait ServiceConfig<'sc>: Default + Clone + Serialize + for<'de> Deserialize<'de> + Sized {
    /// Returns the service name derived automatically from the Rust type name (snake_case).
    fn name() -> &'static str {
        let full_type_name = std::any::type_name::<Self>();
        let type_name = full_type_name.rsplit("::").next().unwrap_or(full_type_name);

        fn to_snake_case(s: &str) -> String {
            let mut snake = String::new();
            for (i, ch) in s.chars().enumerate() {
                if ch.is_uppercase() {
                    if i != 0 {
                        snake.push('_');
                    }
                    for lower in ch.to_lowercase() {
                        snake.push(lower);
                    }
                } else {
                    snake.push(ch);
                }
            }
            snake
        }

        Box::leak(to_snake_case(type_name).into_boxed_str())
    }

    /// Returns the fixed port associated with this service, if any.
    fn port() -> Option<u16>;

    /// Load config from a single toml file path passed in.
    /// The config is expected to have a table named after the service.
    /// If the file or the service config does not exist or fails to deserialize,
    /// returns Self::default().
    fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn Error>> {
        // Try read the file, if not found return default immediately
        let contents = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(Box::new(e)),
        };

        // Parse the whole file as a toml::Value (generic)
        let toml_value: toml::Value = toml::from_str(&contents)?;

        // Get the service-specific table by name
        let service_table = toml_value.get(Self::name());

        match service_table {
            Some(table) => {
                // Deserialize only this table into Self
                let config = table.clone().try_into()?;
                Ok(config)
            }
            None => Ok(Self::default()),
        }
    }
}

pub trait ServiceHandle<'s> {
    type Config: ServiceConfig<'s>;
    type Args;
    type Output;

    fn run(
        node: &Node,
        config: &Self::Config,
        args: Self::Args,
    ) -> Result<(Self::Output, JoinHandle<()>), Box<dyn Error>>;

    fn log(args: std::fmt::Arguments) {
        println!("[{}]: {}", Self::Config::name(), args);
    }
}
