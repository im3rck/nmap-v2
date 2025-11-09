//! ApexScan Core Library
//!
//! This crate provides common types, traits, and utilities used across the ApexScan project.

pub mod error;
pub mod net;
pub mod scan;
pub mod types;
pub mod dns_resolver;
pub mod avm_data;

pub use error::{Error, Result};
