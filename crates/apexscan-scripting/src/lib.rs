//! ApexScan Scripting Engine (ASE)
//!
//! Python-based scripting with NSE compatibility

pub mod python;
pub mod nse;
pub mod engine;
pub mod script;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Script execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptResult {
    pub script_name: String,
    pub output: String,
    pub data: HashMap<String, String>,
    pub success: bool,
    pub error: Option<String>,
}

/// Script context (input data for scripts)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptContext {
    pub target_ip: String,
    pub target_port: Option<u16>,
    pub service_name: Option<String>,
    pub service_version: Option<String>,
    pub os_name: Option<String>,
    pub banner: Option<String>,
}

impl ScriptContext {
    pub fn new(target_ip: String) -> Self {
        Self {
            target_ip,
            target_port: None,
            service_name: None,
            service_version: None,
            os_name: None,
            banner: None,
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.target_port = Some(port);
        self
    }

    pub fn with_service(mut self, service: String, version: Option<String>) -> Self {
        self.service_name = Some(service);
        self.service_version = version;
        self
    }

    pub fn with_os(mut self, os: String) -> Self {
        self.os_name = Some(os);
        self
    }

    pub fn with_banner(mut self, banner: String) -> Self {
        self.banner = Some(banner);
        self
    }
}
