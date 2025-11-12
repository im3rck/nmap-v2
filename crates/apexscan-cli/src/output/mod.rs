//! Output management and formatting

pub mod json;
pub mod xml;
pub mod csv;
pub mod console;
pub mod grepable;

use apexscan_core::scan::{HostResult, ScanResults};
use apexscan_core::Result;

/// Output format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Xml,
    Csv,
    Console,
    Grepable,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "json" => Some(OutputFormat::Json),
            "xml" => Some(OutputFormat::Xml),
            "csv" => Some(OutputFormat::Csv),
            "txt" | "console" => Some(OutputFormat::Console),
            "grepable" | "grep" => Some(OutputFormat::Grepable),
            _ => None,
        }
    }
}

/// Output manager
pub struct OutputManager {
    format: OutputFormat,
    output_file: Option<String>,
}

impl OutputManager {
    pub fn new(format: OutputFormat, output_file: Option<String>) -> Self {
        Self {
            format,
            output_file,
        }
    }

    /// Write scan results
    pub fn write_results(&self, results: &ScanResults) -> Result<()> {
        let output = match self.format {
            OutputFormat::Json => json::format_json(results)?,
            OutputFormat::Xml => xml::format_xml(results)?,
            OutputFormat::Csv => csv::format_csv(results)?,
            OutputFormat::Console => console::format_console(results)?,
            OutputFormat::Grepable => grepable::format_grepable(results),
        };

        if let Some(ref file_path) = self.output_file {
            std::fs::write(file_path, output)
                .map_err(|e| apexscan_core::Error::Other(format!("Failed to write output: {}", e)))?;
            println!("Results written to: {}", file_path);
        } else {
            println!("{}", output);
        }

        Ok(())
    }

    /// Write host result (streaming)
    pub fn write_host_result(&self, host: &HostResult) {
        if self.format == OutputFormat::Console && self.output_file.is_none() {
            console::print_host_result(host);
        }
    }
}
