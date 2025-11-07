//! Script engine coordinator

use crate::{python::PythonExecutor, ScriptContext, ScriptResult};
use apexscan_core::Result;
use std::path::Path;
use tracing::{debug, info};

/// Script engine
pub struct ScriptEngine {
    python_executor: PythonExecutor,
    script_dir: String,
}

impl ScriptEngine {
    pub fn new(script_dir: String) -> Result<Self> {
        let python_executor = PythonExecutor::new()?;

        Ok(Self {
            python_executor,
            script_dir,
        })
    }

    /// Execute a single script
    pub fn execute_script(
        &self,
        script_name: &str,
        context: &ScriptContext,
    ) -> Result<ScriptResult> {
        let script_path = Path::new(&self.script_dir).join(script_name);

        debug!("Executing script: {:?}", script_path);

        self.python_executor
            .execute_script(script_path.to_str().unwrap(), context)
    }

    /// Execute multiple scripts
    pub fn execute_scripts(
        &self,
        script_names: Vec<&str>,
        context: &ScriptContext,
    ) -> Vec<ScriptResult> {
        info!("Executing {} scripts", script_names.len());

        let mut results = Vec::new();

        for script_name in script_names {
            match self.execute_script(script_name, context) {
                Ok(result) => results.push(result),
                Err(e) => {
                    results.push(ScriptResult {
                        script_name: script_name.to_string(),
                        output: String::new(),
                        data: std::collections::HashMap::new(),
                        success: false,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        results
    }

    /// List available scripts
    pub fn list_scripts(&self) -> Result<Vec<String>> {
        let path = Path::new(&self.script_dir);

        if !path.exists() {
            return Ok(Vec::new());
        }

        let mut scripts = Vec::new();

        for entry in std::fs::read_dir(path)
            .map_err(|e| apexscan_core::Error::Other(e.to_string()))?
        {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("py") {
                    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                        scripts.push(name.to_string());
                    }
                }
            }
        }

        Ok(scripts)
    }
}
