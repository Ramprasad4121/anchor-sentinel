//! # Analysis Module
//!
//! @title Advanced Static Analysis Engine
//! @author Ramprasad
//!
//! This module contains advanced analysis capabilities that go beyond
//! simple pattern matching to provide semantic understanding of code.
//!
//! ## Components
//!
//! - **Taint Analysis**: Track untrusted data flow from Sources to Sinks
//! - **Global Context**: Cross-file program understanding
//! - **Control Flow**: CFG-lite for scope-aware analysis

pub mod taint;
pub mod context;
pub mod cfg;

pub use taint::{TaintTracker, TaintContext, TaintStatus, TaintSourceType, TaintSinkType};
pub use context::ProgramContext;
pub use cfg::ScopeTracker;
