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
//! - **Source**: Untrusted data (function args, ctx.accounts) -> Tainted
//! - **Sink**: Dangerous operations (invoke, transfer) -> Vulnerability if input is Tainted
//! - **Sanitizer**: Checks that make data safe (require!) -> Sanitized
//!
//! ## Implementation
//! - `TaintStatus`: Clean, Tainted, Sanitized, Unknown
//! - `TaintContext`: Maps scopes/variables to statuses
//!

use std::collections::{HashMap, HashSet};
use syn::{
    visit::{self, Visit}, Expr, ExprCall, ExprMethodCall, ExprPath, ItemFn, 
    Pat, Local, Stmt, Block, ExprIf, ExprMacro, FnArg, PatIdent,
};

/// Represents the taint status of a variable.
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum TaintStatus {
    /// Safe: Hardcoded constants, trusted values
    Clean,
    /// Unsafe: User input, account data
    Tainted,
    /// Safe: Checked via if/require statements
    Sanitized,
    /// Unknown state
    Unknown,
}

/// Represents a source of tainted (untrusted) data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintSourceType {
    FunctionArg,
    AccountField,
    DeserializedData,
}

/// Represents a dangerous operation (sink) where tainted data is risky.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintSinkType {
    Transfer,
    Invoke,
    ArrayIndex,
    StateModification,
    UncheckedMath,
}

/// A tainted data flow from source to sink.
#[derive(Debug, Clone)]
pub struct TaintedFlow {
    pub variable: String,
    pub sink: TaintSinkType,
    pub line: usize,
    pub code: String,
}

/// Tracks variables and their taint status.
#[derive(Debug, Default)]
pub struct TaintContext {
    /// Maps variable name "x" -> TaintStatus
    pub variables: HashMap<String, TaintStatus>,
}

impl TaintContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_status(&mut self, var: String, status: TaintStatus) {
        self.variables.insert(var, status);
    }

    pub fn get_status(&self, var: &str) -> TaintStatus {
        *self.variables.get(var).unwrap_or(&TaintStatus::Unknown)
    }
}

/// Tracks taint propagation through a function using the Visitor pattern.
#[derive(Debug)]
pub struct TaintTracker {
    /// The current context of variable statuses
    pub context: TaintContext,
    /// Detected unsafe flows
    pub flows: Vec<TaintedFlow>,
    /// Current source code for line extraction
    source_lines: Vec<String>,
}

impl TaintTracker {
    /// Creates a new taint tracker.
    pub fn new(source_code: &str) -> Self {
        Self {
            context: TaintContext::new(),
            flows: Vec::new(),
            source_lines: source_code.lines().map(|s| s.to_string()).collect(),
        }
    }

    /// Records a tainted flow to a sink.
    pub fn record_flow(&mut self, var: &str, sink: TaintSinkType, line: usize) {
        let status = self.context.get_status(var);
        
        // Only report if the variable is undeniably Tainted
        // If it is Sanitized, Clean, or Unknown, we don't report.
        if status == TaintStatus::Tainted {
            let code = self.source_lines.get(line.saturating_sub(1))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
                
            self.flows.push(TaintedFlow {
                variable: var.to_string(),
                sink,
                line,
                code,
            });
        }
    }

    /// Analyzes a function for tainted data flows.
    pub fn analyze_function(&mut self, func: &ItemFn) {
        // Step 1: Mark all function arguments as Tainted
        for arg in &func.sig.inputs {
            if let FnArg::Typed(pat_type) = arg {
                if let Pat::Ident(PatIdent { ident, .. }) = &*pat_type.pat {
                    self.context.set_status(ident.to_string(), TaintStatus::Tainted);
                }
            }
        }
        
        // Special handling for 'ctx' -> Tainted
        self.context.set_status("ctx".to_string(), TaintStatus::Tainted);
        
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

impl<'a> TaintVisitor<'a> {
    /// Recursively analyzes an expression to determine its aggregate TaintStatus.
    /// If ANY part of the expression is Tainted, the result is Tainted.
    /// If ANY part is Unknown (and no parts are Tainted), result is Unknown.
    /// Otherwise Clean.
    fn analyze_expr(&self, expr: &Expr) -> TaintStatus {
        match expr {
            Expr::Path(path) => {
                if let Some(ident) = path.path.get_ident() {
                    self.tracker.context.get_status(&ident.to_string())
                } else {
                    // Complex paths like ctx.accounts.user are mostly Tainted if base is tainted
                    // Or check segment by segment.
                    // For now, let's extract variables and check them.
                    let vars = extract_variables(expr);
                    let mut final_status = TaintStatus::Clean;
                    for var in vars {
                        let status = self.tracker.context.get_status(&var);
                        if status == TaintStatus::Tainted {
                            return TaintStatus::Tainted;
                        } else if status == TaintStatus::Unknown {
                            final_status = TaintStatus::Unknown;
                        }
                    }
                    final_status
                }
            },
            Expr::Binary(bin) => {
                let left = self.analyze_expr(&bin.left);
                let right = self.analyze_expr(&bin.right);
                if left == TaintStatus::Tainted || right == TaintStatus::Tainted {
                    TaintStatus::Tainted
                } else if left == TaintStatus::Unknown || right == TaintStatus::Unknown {
                    TaintStatus::Unknown
                } else {
                    TaintStatus::Clean
                }
            },
            Expr::Lit(_) => TaintStatus::Clean,
            Expr::Call(_call) => {
                // If calling a function with tainted args...
                TaintStatus::Unknown 
            },
            Expr::Paren(p) => self.analyze_expr(&p.expr),
            Expr::Unary(u) => self.analyze_expr(&u.expr),
            _ => {
                // Check all sub-variables
                let vars = extract_variables(expr);
                for var in vars {
                    if self.tracker.context.get_status(&var) == TaintStatus::Tainted {
                        return TaintStatus::Tainted;
                    }
                }
                TaintStatus::Unknown
            }
        }
    }
}

impl<'a> Visit<'a> for TaintVisitor<'a> {
    fn visit_local(&mut self, local: &'a Local) {
        // Logic for: let y = x + 10;
        if let Some(init) = &local.init {
            // 1. Analyze the expression on the right
            let rhs_status = self.analyze_expr(&init.expr);

            // 2. If valid pattern on LHS
            if let Pat::Ident(PatIdent { ident, .. }) = &local.pat {
                 // 3. Update the variable's status in map
                 self.tracker.context.set_status(ident.to_string(), rhs_status);
            }
        }
        
        visit::visit_local(self, local);
    }
    
    fn visit_stmt(&mut self, i: &'a Stmt) {
        // Approximate line number (since we don't have Span info easily without proc_macro2)
        // In a real compiler plugin we'd use spans.
        self.current_line += 1; 
        visit::visit_stmt(self, i);
    }

    fn visit_expr_call(&mut self, node: &'a ExprCall) {
        let call_str = quote::quote!(#node).to_string();
        let lower = call_str.to_lowercase();
        
        // Detect sinks
        if lower.contains("transfer") && !lower.contains("transfer_checked") {
            for arg in &node.args {
                let vars = extract_variables(arg);
                for var in vars {
                     self.tracker.record_flow(&var, TaintSinkType::Transfer, self.current_line);
                }
            }
        }
        
        if lower.contains("invoke") {
            for arg in &node.args {
                let vars = extract_variables(arg);
                for var in vars {
                    self.tracker.record_flow(&var, TaintSinkType::Invoke, self.current_line);
                }
            }
        }
        
        visit::visit_expr_call(self, node);
    }
    
    fn visit_expr_method_call(&mut self, node: &'a ExprMethodCall) {
        let method = node.method.to_string();
        
        // SANITIZERS: checked_*, saturating_*
        if method.starts_with("checked_") || method.starts_with("saturating_") {
             // The result of this call is Sanitized/Clean (scope dependent, but usually result is safe)
             // But wait, the expression itself evaluates to something safe.
             // But if we do: let x = tainted.checked_add(10).unwrap();
             // visit_local will see RHS as... well, result of checked_add is Option. 
             // If we unwrap, we get the value.
             // For now, let's treat the receiver as being sanitized in place? No, that's not right.
             // The *result* is sanitized. 
             // Logic in analyze_expr should handle MethodCall. 
             // If we see checked_*, return Clean/Sanitized.
        }

        // SINKS: transfer
        if method == "transfer" {
             for arg in &node.args {
                let vars = extract_variables(arg);
                for var in vars {
                    self.tracker.record_flow(&var, TaintSinkType::Transfer, self.current_line);
                }
            }
        }
        
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'a ExprMacro) {
        let macro_name = node.mac.path.segments.last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        
        // SANITIZERS: require!(...), assert!(...)
        if macro_name == "require" || macro_name == "assert" || macro_name == "require_eq" {
             // Variables used in these macros become Sanitized
             let tokens_str = node.mac.tokens.to_string();
             let vars = extract_vars_from_str(&tokens_str);
             
             for var in vars {
                 // Check if it was Tainted
                 if self.tracker.context.get_status(&var) == TaintStatus::Tainted {
                     // Mark as Sanitized
                     self.tracker.context.set_status(var, TaintStatus::Sanitized);
                 }
             }
        }
        
        visit::visit_expr_macro(self, node);
    }
    
    fn visit_expr_if(&mut self, node: &'a ExprIf) {
        // SANITIZERS: if checks
        let cond_vars = extract_variables(&node.cond);
        
        // Clone context for the branch? 
        // Variables checked in 'if' condition are Sanitized *inside the block*.
        // This requires scope-aware context tracking (push/pop scopes).
        // For this simple version, we'll simpler logic:
        // We mark them sanitized globally (simple linear scan approximation) 
        // OR we just mark them sanitized.
        
        let mut vars_to_restore = Vec::new();
        
        for var in cond_vars {
            if self.tracker.context.get_status(&var) == TaintStatus::Tainted {
                self.tracker.context.set_status(var.clone(), TaintStatus::Sanitized);
                vars_to_restore.push(var);
            }
        }
        
        // Visit block with these vars sanitized
        visit::visit_block(self, &node.then_branch);
        
        // Restore status? (Ideally yes, if checked only inside if)
        // For now, let's be conservative. If you check it, it's safer.
        // But if you check it in one branch, it is NOT safe in else branch or after.
        // True flow sensitive analysis is hard.
        // We will restore for now to avoid false negatives (missing bugs).
        for var in vars_to_restore {
             self.tracker.context.set_status(var, TaintStatus::Tainted);
        }
        
        if let Some((_, else_branch)) = &node.else_branch {
            visit::visit_expr(self, else_branch);
        }
    }
}

/// Helper to extract variable names from an expression.
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
        Expr::Field(field) => extract_vars_recursive(&field.base, vars),
        Expr::Binary(binary) => {
            extract_vars_recursive(&binary.left, vars);
            extract_vars_recursive(&binary.right, vars);
        }
        Expr::Call(call) => {
            for arg in &call.args { extract_vars_recursive(arg, vars); }
        }
        Expr::MethodCall(method) => {
            extract_vars_recursive(&method.receiver, vars);
            for arg in &method.args { extract_vars_recursive(arg, vars); }
        }
        Expr::Paren(paren) => extract_vars_recursive(&paren.expr, vars),
        Expr::Unary(unary) => extract_vars_recursive(&unary.expr, vars),
        _ => {}
    }
}

fn extract_vars_from_str(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric() && c != '_')
     .filter(|w| !w.is_empty() && w.chars().next().unwrap().is_alphabetic())
     .map(|w| w.to_string())
     .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_status() {
        let mut context = TaintContext::new();
        context.set_status("x".to_string(), TaintStatus::Tainted);
        assert_eq!(context.get_status("x"), TaintStatus::Tainted);
        assert_eq!(context.get_status("y"), TaintStatus::Unknown);
    }
    
    #[test]
    fn test_taint_propagation_logic() {
        // Can't easily test Visit without mocking syn structures, 
        // but we can test the TaintTracker logic if we exposed the propagation helper
        // Since logic is inside Visit impl, we rely on Source Code integration tests mostly.
    }
}
