//! Tool system for EpiGraph agentic framework
//!
//! Tools are typed operations that agents can invoke. Every tool execution
//! produces provenance metadata linking the output to the invoking agent,
//! task, and correlation context.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use epigraph_core::domain::AgentId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

/// Error type for tool operations
#[derive(Error, Debug)]
pub enum ToolError {
    #[error("Tool '{0}' not found in registry")]
    NotFound(String),
    #[error("Tool execution failed: {0}")]
    ExecutionFailed(String),
    #[error("Tool execution timed out after {0:?}")]
    Timeout(Duration),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Agent lacks required capability: {0}")]
    Unauthorized(String),
}

/// Context provided to tool execution
#[derive(Debug, Clone)]
pub struct ToolContext {
    /// Agent invoking the tool
    pub agent_id: AgentId,
    /// Task this tool is being invoked for (if any)
    pub task_id: Option<Uuid>,
    /// Correlation ID for tracing
    pub correlation_id: String,
    /// Timeout for this invocation
    pub timeout: Duration,
}

/// Tool output with provenance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOutput {
    /// Output data
    pub data: serde_json::Value,
    /// Execution duration
    pub duration_ms: u64,
    /// Timestamp of execution
    pub executed_at: DateTime<Utc>,
}

/// Descriptor for a tool (for listing without invoking)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDescriptor {
    pub id: String,
    pub name: String,
    pub description: String,
    pub input_schema: Option<serde_json::Value>,
    pub output_schema: Option<serde_json::Value>,
}

/// A tool that agents can invoke
#[async_trait]
pub trait Tool: Send + Sync {
    /// Unique tool identifier
    fn id(&self) -> &str;
    /// Human-readable name
    fn name(&self) -> &str;
    /// Tool description
    fn description(&self) -> &str;
    /// Execute the tool
    async fn execute(
        &self,
        input: serde_json::Value,
        context: ToolContext,
    ) -> Result<ToolOutput, ToolError>;
    /// Get descriptor
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            id: self.id().to_string(),
            name: self.name().to_string(),
            description: self.description().to_string(),
            input_schema: None,
            output_schema: None,
        }
    }
}

/// Registry of available tools
pub struct ToolRegistry {
    tools: HashMap<String, Arc<dyn Tool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    /// Register a tool
    pub fn register(&mut self, tool: impl Tool + 'static) {
        self.tools.insert(tool.id().to_string(), Arc::new(tool));
    }

    /// Get a tool by ID
    pub fn get(&self, id: &str) -> Option<Arc<dyn Tool>> {
        self.tools.get(id).cloned()
    }

    /// List all available tools
    pub fn list(&self) -> Vec<ToolDescriptor> {
        self.tools.values().map(|t| t.descriptor()).collect()
    }

    /// Number of registered tools
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Is the registry empty?
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EchoTool;

    #[async_trait]
    impl Tool for EchoTool {
        fn id(&self) -> &str {
            "echo"
        }
        fn name(&self) -> &str {
            "Echo"
        }
        fn description(&self) -> &str {
            "Returns input as output"
        }
        async fn execute(
            &self,
            input: serde_json::Value,
            _ctx: ToolContext,
        ) -> Result<ToolOutput, ToolError> {
            Ok(ToolOutput {
                data: input,
                duration_ms: 0,
                executed_at: Utc::now(),
            })
        }
    }

    fn test_context() -> ToolContext {
        ToolContext {
            agent_id: AgentId::new(),
            task_id: None,
            correlation_id: "test-123".to_string(),
            timeout: Duration::from_secs(30),
        }
    }

    #[test]
    fn test_registry_register_and_get() {
        let mut registry = ToolRegistry::new();
        registry.register(EchoTool);
        assert_eq!(registry.len(), 1);
        assert!(registry.get("echo").is_some());
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn test_registry_list() {
        let mut registry = ToolRegistry::new();
        registry.register(EchoTool);
        let tools = registry.list();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].id, "echo");
        assert_eq!(tools[0].name, "Echo");
    }

    #[tokio::test]
    async fn test_tool_execution() {
        let tool = EchoTool;
        let input = serde_json::json!({"message": "hello"});
        let output = tool.execute(input.clone(), test_context()).await.unwrap();
        assert_eq!(output.data, input);
    }

    #[test]
    fn test_empty_registry() {
        let registry = ToolRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }
}
