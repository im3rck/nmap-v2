//! JSON output formatter

use apexscan_core::scan::ScanResults;
use apexscan_core::Result;
use serde_json;

pub fn format_json(results: &ScanResults) -> Result<String> {
    serde_json::to_string_pretty(results)
        .map_err(|e| apexscan_core::Error::Other(format!("JSON serialization failed: {}", e)))
}
