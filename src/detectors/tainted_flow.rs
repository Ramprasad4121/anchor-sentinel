//! # Tainted Data Flow Detector
//!
//! @title V023 - Tainted Data Flow Detection
//! @author Ramprasad
//!
//! Uses taint analysis to detect untrusted user input flowing to
//! dangerous operations (sinks) without proper validation (sanitizers).
//!
//! ## Detection Strategy
//!
//! 1. Mark all function arguments as tainted (Sources)
//! 2. Propagate taint through variable assignments
//! 3. Flag when tainted data reaches Sinks without Sanitizers
//!
//! ## Vulnerability Pattern
//!
//! ```rust,ignore
//! // 'amount' is tainted (Source: function arg)
//! pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
//!     // No require! or bounds check (missing Sanitizer)
//!     token::transfer(ctx, amount)?; // BUG: Tainted data at Sink
//! }
//! ```
//!
//! ## CWE Reference
//!
//! - CWE-20: Improper Input Validation

use crate::detectors::VulnerabilityDetector;
use crate::parser::AnalysisContext;
use crate::report::{Finding, Severity};
use crate::analysis::taint::{TaintTracker, TaintSinkType}; // TaintSourceType removed from flow
use syn::ItemFn;

/// Detector for tainted data flow vulnerabilities.
pub struct TaintedFlowDetector;

impl TaintedFlowDetector {
    /// Creates a new tainted flow detector instance.
    pub fn new() -> Self {
        Self
    }

    /// Extracts all function definitions from the source.
    fn extract_functions(&self, source: &str) -> Vec<ItemFn> {
        let mut functions = Vec::new();
        
        if let Ok(syntax) = syn::parse_file(source) {
            for item in syntax.items {
                if let syn::Item::Fn(func) = item {
                    // Check if this looks like an instruction (has ctx parameter)
                    let has_ctx = func.sig.inputs.iter().any(|arg| {
                        if let syn::FnArg::Typed(pt) = arg {
                            let ty = quote::quote!(#pt.ty).to_string();
                            ty.contains("Context")
                        } else {
                            false
                        }
                    });
                    
                    if has_ctx {
                        functions.push(func);
                    }
                }
            }
        }
        
        functions
    }
}

impl VulnerabilityDetector for TaintedFlowDetector {
    fn id(&self) -> &'static str { "V023" }
    
    fn name(&self) -> &'static str { "Tainted Data Flow" }
    
    fn description(&self) -> &'static str {
        "Detects untrusted user input reaching dangerous operations without validation."
    }
    
    fn severity(&self) -> Severity { Severity::High }
    
    fn cwe(&self) -> Option<&'static str> { Some("CWE-20") }
    
    fn remediation(&self) -> &'static str {
        "Validate all user inputs before use:\n\
         require!(amount > 0 && amount <= MAX_AMOUNT, ErrorCode::InvalidAmount);"
    }

    fn detect(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let source = &context.source_code;
        
        // Extract instruction functions
        let functions = self.extract_functions(source);
        
        for func in functions {
            let mut tracker = TaintTracker::new(source);
            tracker.analyze_function(&func);
            
            // Convert tainted flows to findings
            for flow in tracker.flows {
                let sink_desc = match flow.sink {
                    TaintSinkType::Transfer => "token transfer",
                    TaintSinkType::Invoke => "cross-program invocation",
                    TaintSinkType::ArrayIndex => "array indexing",
                    TaintSinkType::StateModification => "state modification",
                    TaintSinkType::UncheckedMath => "unchecked arithmetic",
                };
                
                findings.push(Finding {
                    id: format!("V023-{}", flow.line),
                    detector_id: self.id().to_string(),
                    title: format!("Tainted '{}' flows to {} without validation", 
                                   flow.variable, sink_desc),
                    description: format!(
                        "Untrusted data in variable '{}' reaches a {} operation without \
                         being validated. Attackers can exploit this to cause unexpected behavior.",
                        flow.variable, sink_desc
                    ),
                    severity: self.severity(),
                    file_path: context.file_path.clone(),
                    line: flow.line,
                    location: format!("{}:{}", context.file_path, flow.line),
                    code_snippet: Some(flow.code),
                    remediation: self.remediation().to_string(),
                    cwe: self.cwe().map(|s| s.to_string()),
                    confidence: 0.85,
                });
            }
        }
        
        findings
    }
}

impl Default for TaintedFlowDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::taint::{TaintContext, TaintStatus};

    #[test]
    fn test_taint_context_status() {
        let mut context = TaintContext::new();
        context.set_status("amount".to_string(), TaintStatus::Tainted);
        
        assert_eq!(context.get_status("amount"), TaintStatus::Tainted);
        assert_eq!(context.get_status("safe"), TaintStatus::Unknown);
    }
}
