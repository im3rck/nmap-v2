//! Script metadata and management

use serde::{Deserialize, Serialize};

/// Script metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptMetadata {
    pub name: String,
    pub description: String,
    pub author: String,
    pub categories: Vec<ScriptCategory>,
    pub requires_port: bool,
    pub requires_service: bool,
}

/// Script category (matches NSE categories)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptCategory {
    Auth,
    Broadcast,
    Brute,
    Default,
    Discovery,
    Dos,
    Exploit,
    External,
    Fuzzer,
    Intrusive,
    Malware,
    Safe,
    Version,
    Vuln,
}

impl ScriptCategory {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "auth" => Some(ScriptCategory::Auth),
            "broadcast" => Some(ScriptCategory::Broadcast),
            "brute" => Some(ScriptCategory::Brute),
            "default" => Some(ScriptCategory::Default),
            "discovery" => Some(ScriptCategory::Discovery),
            "dos" => Some(ScriptCategory::Dos),
            "exploit" => Some(ScriptCategory::Exploit),
            "external" => Some(ScriptCategory::External),
            "fuzzer" => Some(ScriptCategory::Fuzzer),
            "intrusive" => Some(ScriptCategory::Intrusive),
            "malware" => Some(ScriptCategory::Malware),
            "safe" => Some(ScriptCategory::Safe),
            "version" => Some(ScriptCategory::Version),
            "vuln" => Some(ScriptCategory::Vuln),
            _ => None,
        }
    }
}

impl ToString for ScriptCategory {
    fn to_string(&self) -> String {
        match self {
            ScriptCategory::Auth => "auth",
            ScriptCategory::Broadcast => "broadcast",
            ScriptCategory::Brute => "brute",
            ScriptCategory::Default => "default",
            ScriptCategory::Discovery => "discovery",
            ScriptCategory::Dos => "dos",
            ScriptCategory::Exploit => "exploit",
            ScriptCategory::External => "external",
            ScriptCategory::Fuzzer => "fuzzer",
            ScriptCategory::Intrusive => "intrusive",
            ScriptCategory::Malware => "malware",
            ScriptCategory::Safe => "safe",
            ScriptCategory::Version => "version",
            ScriptCategory::Vuln => "vuln",
        }
        .to_string()
    }
}
