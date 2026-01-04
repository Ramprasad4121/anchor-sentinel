//! # Taint Analysis Engine
//!
//! @title Data Flow Taint Tracking
//! @author Ramprasad
//!
//! Implements taint analysis to track untrusted data flow from Sources
//! (user input) to Sinks (dangerous operations) without Sanitizers (checks).
//!
//! ## Concept
//!
//! - **Source**: Untrusted data (function args, ctx.accounts, deserialized data)
//! - **Sink**: Dangerous operations (invoke, transfer, array indexing)
//! - **Sanitizer**: Checks that make data safe (require!, if conditions)
//!
//! ## Example Detection
//!
//! ```rust,ignore
//! // 'amount' is Source (function argument)
//! pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
//!     // No sanitizer (missing require! or bounds check)
//!     token::transfer(..., amount)?; // FLAGGED: Tainted var hits Sink
//! }
//! ```

use std::collections::{HashMap, HashSet};
use syn::{
    visit::Visit, Expr, ExprCall, ExprMethodCall, ExprPath, ItemFn, 
    Pat, Local, Stmt, Block, ExprIf, ExprMacro, FnArg, PatIdent,
};

/// Represents a source of tainted (untrusted) data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintSource {
    /// Function argument: `fn foo(amount: u64)` - amount is tainted
    FunctionArg(String),
    /// Account field: `ctx.accounts.user` - untrusted
    AccountField(String),
    /// Deserialized data from user input
    DeserializedData(String),
    /// Data read from an account
    AccountData(String),
}

/// Represents a dangerous operation (sink) where tainted data is risky.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintSink {
    /// token::transfer, anchor_spl::token::transfer
    Transfer,
    /// invoke() / invoke_signed()
    Invoke,
    /// Array indexing with tainted index
    ArrayIndex,
    /// Direct state modification: account.data = tainted
    StateModification,
    /// Math operations without checked arithmetic
    UncheckedMath,
}

/// Represents a check that sanitizes tainted data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Sanitizer {
    /// require! macro: require!(amount > 0)
    RequireMacro,
    /// If condition: if amount > 0 { ... }
    IfCondition,
    /// Checked math: .checked_add(), .checked_sub()
    CheckedMath,
    /// Explicit bounds check
    BoundsCheck,
    /// Assert macro
    AssertMacro,
}

/// A tainted data flow from source to sink.
#[derive(Debug, Clone)]
pub struct TaintedFlow {
    /// The original source of the taint
    pub source: TaintSource,
    /// The variable that carries the taint
    pub variable: String,
    /// The sink where tainted data is used unsafely
    pub sink: TaintSink,
    /// Line number where the vulnerability occurs
    pub line: usize,
    /// Code snippet
    pub code: String,
}

/// Tracks taint propagation through a function.
#[derive(Debug)]
pub struct TaintTracker {
    /// Variables currently marked as tainted
    tainted_vars: HashSet<String>,
    /// Variables that have been sanitized
    sanitized_vars: HashSet<String>,
    /// Map from variable to its source
    taint_sources: HashMap<String, TaintSource>,
    /// Detected unsafe flows
    pub flows: Vec<TaintedFlow>,
    /// Current source code for line extraction
    source_lines: Vec<String>,
}

impl TaintTracker {
    /// Creates a new taint tracker.
    pub fn new(source_code: &str) -> Self {
        Self {
            tainted_vars: HashSet::new(),
            sanitized_vars: HashSet::new(),
            taint_sources: HashMap::new(),
            flows: Vec::new(),
            source_lines: source_code.lines().map(|s| s.to_string()).collect(),
        }
    }

    /// Marks a variable as tainted from a source.
    pub fn mark_tainted(&mut self, var: &str, source: TaintSource) {
        self.tainted_vars.insert(var.to_string());
        self.taint_sources.insert(var.to_string(), source);
    }

    /// Marks a variable as sanitized.
    pub fn mark_sanitized(&mut self, var: &str) {
        self.sanitized_vars.insert(var.to_string());
    }

    /// Checks if a variable is tainted and not sanitized.
    pub fn is_tainted(&self, var: &str) -> bool {
        self.tainted_vars.contains(var) && !self.sanitized_vars.contains(var)
    }

    /// Propagates taint from source to destination.
    /// If `src` is tainted, `dst` becomes tainted.
    pub fn propagate(&mut self, src: &str, dst: &str) {
        if self.is_tainted(src) {
            if let Some(source) = self.taint_sources.get(src).cloned() {
                self.mark_tainted(dst, source);
            }
        }
    }

    /// Records a tainted flow to a sink.
    pub fn record_flow(&mut self, var: &str, sink: TaintSink, line: usize) {
        if self.is_tainted(var) {
            if let Some(source) = self.taint_sources.get(var).cloned() {
                let code = self.source_lines.get(line.saturating_sub(1))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                    
                self.flows.push(TaintedFlow {
                    source,
                    variable: var.to_string(),
                    sink,
                    line,
                    code,
                });
            }
        }
    }

    /// Analyzes a function for tainted data flows.
    pub fn analyze_function(&mut self, func: &ItemFn) {
        // Step 1: Mark all function arguments as tainted
        for arg in &func.sig.inputs {
            if let FnArg::Typed(pat_type) = arg {
                if let Pat::Ident(PatIdent { ident, .. }) = &*pat_type.pat {
                    let arg_name = ident.to_string();
                    self.mark_tainted(&arg_name, TaintSource::FunctionArg(arg_name.clone()));
                }
            }
        }
        
        // Special handling for 'ctx' - mark ctx.accounts.* as tainted
        self.mark_tainted("ctx", TaintSource::AccountField("ctx".to_string()));
        
        // Step 2: Visit the function body
        let mut visitor = TaintVisitor {
            tracker: self,
            current_line: 0,
        };
        visitor.visit_block(&func.block);
    }
}

/// AST Visitor for taint propagation and sink detection.
struct TaintVisitor<'a> {
    tracker: &'a mut TaintTracker,
    current_line: usize,
}

impl<'a> Visit<'a> for TaintVisitor<'_> {
    fn visit_local(&mut self, local: &'a Local) {
        // Track variable assignments: let y = x;
        if let Pat::Ident(PatIdent { ident, .. }) = &local.pat {
            let dst = ident.to_string();
            
            if let Some(init) = &local.init {
                // Check if the initializer contains tainted variables
                let src_vars = extract_variables(&init.expr);
                for src in src_vars {
                    self.tracker.propagate(&src, &dst);
                }
            }
        }
        
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, node: &'a ExprCall) {
        let call_str = quote::quote!(#node).to_string();
        let lower = call_str.to_lowercase();
        
        // Detect sinks
        if lower.contains("transfer") && !lower.contains("transfer_checked") {
            // Check if any argument is tainted
            for arg in &node.args {
                let vars = extract_variables(arg);
                for var in vars {
                    self.tracker.record_flow(&var, TaintSink::Transfer, self.current_line);
                }
            }
        }
        
        if lower.contains("invoke") {
            for arg in &node.args {
                let vars = extract_variables(arg);
                for var in vars {
                    self.tracker.record_flow(&var, TaintSink::Invoke, self.current_line);
                }
            }
        }
        
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'a ExprMethodCall) {
        let method = node.method.to_string().to_lowercase();
        
        // Detect sanitizers (checked math)
        if method.starts_with("checked_") || method.starts_with("saturating_") {
            // Extract the receiver variable and mark as sanitized
            let vars = extract_variables(&node.receiver);
            for var in vars {
                self.tracker.mark_sanitized(&var);
            }
        }
        
        // Detect sinks
        if method == "transfer" {
            for arg in &node.args {
                let vars = extract_variables(arg);
                for var in vars {
                    self.tracker.record_flow(&var, TaintSink::Transfer, self.current_line);
                }
            }
        }
        
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'a ExprMacro) {
        let macro_name = node.mac.path.segments.last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        
        // Detect sanitizers (require!, assert!)
        if macro_name == "require" || macro_name == "assert" || macro_name == "require_eq" {
            // Variables in require! conditions are sanitized
            let tokens_str = node.mac.tokens.to_string();
            let words: Vec<&str> = tokens_str.split(|c: char| !c.is_alphanumeric() && c != '_')
                .filter(|s| !s.is_empty())
                .collect();
            
            for word in words {
                if self.tracker.tainted_vars.contains(word) {
                    self.tracker.mark_sanitized(word);
                }
            }
        }
        
        syn::visit::visit_expr_macro(self, node);
    }

    fn visit_expr_if(&mut self, node: &'a ExprIf) {
        // Variables checked in if conditions are sanitized within the block
        let cond_vars = extract_variables(&node.cond);
        for var in cond_vars {
            if self.tracker.is_tainted(&var) {
                self.tracker.mark_sanitized(&var);
            }
        }
        
        syn::visit::visit_expr_if(self, node);
    }
}

/// Extracts variable names from an expression.
fn extract_variables(expr: &Expr) -> Vec<String> {
    let mut vars = Vec::new();
    extract_vars_recursive(expr, &mut vars);
    vars
}

fn extract_vars_recursive(expr: &Expr, vars: &mut Vec<String>) {
    match expr {
        Expr::Path(ExprPath { path, .. }) => {
            if let Some(ident) = path.get_ident() {
                vars.push(ident.to_string());
            } else if let Some(segment) = path.segments.first() {
                vars.push(segment.ident.to_string());
            }
        }
        Expr::Field(field) => {
            extract_vars_recursive(&field.base, vars);
        }
        Expr::Binary(binary) => {
            extract_vars_recursive(&binary.left, vars);
            extract_vars_recursive(&binary.right, vars);
        }
        Expr::Call(call) => {
            for arg in &call.args {
                extract_vars_recursive(arg, vars);
            }
        }
        Expr::MethodCall(method) => {
            extract_vars_recursive(&method.receiver, vars);
            for arg in &method.args {
                extract_vars_recursive(arg, vars);
            }
        }
        Expr::Reference(reference) => {
            extract_vars_recursive(&reference.expr, vars);
        }
        Expr::Paren(paren) => {
            extract_vars_recursive(&paren.expr, vars);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_tracking_basic() {
        let mut tracker = TaintTracker::new("");
        
        // Mark 'amount' as tainted from function arg
        tracker.mark_tainted("amount", TaintSource::FunctionArg("amount".to_string()));
        
        assert!(tracker.is_tainted("amount"));
        assert!(!tracker.is_tainted("other"));
    }

    #[test]
    fn test_taint_propagation() {
        let mut tracker = TaintTracker::new("");
        
        tracker.mark_tainted("x", TaintSource::FunctionArg("x".to_string()));
        tracker.propagate("x", "y");
        
        assert!(tracker.is_tainted("y"));
    }

    #[test]
    fn test_sanitization() {
        let mut tracker = TaintTracker::new("");
        
        tracker.mark_tainted("amount", TaintSource::FunctionArg("amount".to_string()));
        tracker.mark_sanitized("amount");
        
        assert!(!tracker.is_tainted("amount"));
    }
}
