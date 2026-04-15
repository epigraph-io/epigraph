//! LLM enrichment module for epistemic commit analysis
//!
//! Provides abstractions for using LLMs to extract semantic relationships
//! between commits, assess evidence quality, and generate embeddings.

pub mod confidence;
pub mod llm_client;
pub mod prompts;
