//! Python script execution via PyO3

use crate::{ScriptContext, ScriptResult};
use apexscan_core::{Error, Result};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule};
use std::collections::HashMap;
use tracing::{debug, trace, warn};

/// Python script executor
pub struct PythonExecutor {
    initialized: bool,
}

impl PythonExecutor {
    pub fn new() -> Result<Self> {
        // Python interpreter is auto-initialized by pyo3
        Ok(Self { initialized: true })
    }

    /// Execute a Python script
    pub fn execute_script(
        &self,
        script_path: &str,
        context: &ScriptContext,
    ) -> Result<ScriptResult> {
        debug!("Executing Python script: {}", script_path);

        Python::with_gil(|py| {
            // Load the script module
            let script_code = std::fs::read_to_string(script_path)
                .map_err(|e| Error::Script(format!("Failed to read script: {}", e)))?;

            let module = PyModule::from_code(
                py,
                &script_code,
                script_path,
                "apexscan_script",
            )
            .map_err(|e| Error::Script(format!("Failed to load script: {}", e)))?;

            // Create context dictionary
            let ctx_dict = Self::context_to_pydict(py, context)?;

            // Call the main() function if it exists
            let result = if let Ok(main_func) = module.getattr("main") {
                main_func
                    .call1((ctx_dict,))
                    .map_err(|e| Error::Script(format!("Script execution failed: {}", e)))?
            } else {
                return Err(Error::Script("Script missing main() function".to_string()));
            };

            // Parse result
            Self::parse_script_result(py, result, script_path)
        })
    }

    /// Convert ScriptContext to Python dictionary
    fn context_to_pydict<'a>(py: Python<'a>, context: &ScriptContext) -> Result<&'a PyDict> {
        let dict = PyDict::new(py);

        // Map struct field names to what Python scripts expect
        dict.set_item("target", &context.target_ip)
            .map_err(|e| Error::Script(format!("Failed to set context: {}", e)))?;

        if let Some(port) = context.target_port {
            dict.set_item("port", port)
                .map_err(|e| Error::Script(format!("Failed to set port: {}", e)))?;
        }

        if let Some(ref service) = context.service_name {
            dict.set_item("service", service)
                .map_err(|e| Error::Script(format!("Failed to set service: {}", e)))?;
        }

        if let Some(ref version) = context.service_version {
            dict.set_item("version", version)
                .map_err(|e| Error::Script(format!("Failed to set version: {}", e)))?;
        }

        if let Some(ref os) = context.os_name {
            dict.set_item("os", os)
                .map_err(|e| Error::Script(format!("Failed to set os: {}", e)))?;
        }

        if let Some(ref banner) = context.banner {
            dict.set_item("banner", banner)
                .map_err(|e| Error::Script(format!("Failed to set banner: {}", e)))?;
        }

        Ok(dict)
    }

    /// Parse script result from Python
    fn parse_script_result(
        py: Python,
        result: &PyAny,
        script_name: &str,
    ) -> Result<ScriptResult> {
        // Expect a dictionary result
        if let Ok(dict) = result.downcast::<PyDict>() {
            let output = dict
                .get_item("output")
                .map_err(|_| Error::Script("Failed to get output".to_string()))?
                .map(|o| o.extract::<String>().unwrap_or_default())
                .unwrap_or_default();

            let success = dict
                .get_item("success")
                .map_err(|_| Error::Script("Failed to get success".to_string()))?
                .map(|s| s.extract::<bool>().unwrap_or(true))
                .unwrap_or(true);

            let error = dict
                .get_item("error")
                .map_err(|_| Error::Script("Failed to get error".to_string()))?
                .and_then(|e| e.extract::<String>().ok());

            // Extract data dictionary
            let mut data = HashMap::new();
            if let Ok(Some(data_dict)) = dict.get_item("data") {
                if let Ok(d) = data_dict.downcast::<PyDict>() {
                    for (key, value) in d.iter() {
                        if let (Ok(k), Ok(v)) = (key.extract::<String>(), value.extract::<String>()) {
                            data.insert(k, v);
                        }
                    }
                }
            }

            Ok(ScriptResult {
                script_name: script_name.to_string(),
                output,
                data,
                success,
                error,
            })
        } else {
            // If not a dict, convert to string
            let output = result.to_string();
            Ok(ScriptResult {
                script_name: script_name.to_string(),
                output,
                data: HashMap::new(),
                success: true,
                error: None,
            })
        }
    }
}

impl Default for PythonExecutor {
    fn default() -> Self {
        Self::new().expect("Failed to initialize Python")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_executor() {
        let executor = PythonExecutor::new().unwrap();
        assert!(executor.initialized);
    }
}
