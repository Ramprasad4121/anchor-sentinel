//! # Control Flow Graph Lite
//!
//! @title Scope-Aware Analysis with AST
//! @author Ramprasad
//!
//! Uses `syn` AST analysis to track variable validation scopes.
//! Detects when validations are confined to a block (e.g. inside `if`)
//! but sensitive operations happen outside that block.
//!
//! ## Algorithm
//!
//! 1. Traverse AST using `syn::visit::Visit`.
//! 2. Track scope depth (increment on `ExprBlock`, `ExprIf` branches, `ExprLoop`).
//! 3. Track where variables are validated (require/if/checked_math).
//! 4. Track where variables are used in sensitive ops (transfer/cpi).
//! 5. Vulnerability: Usage Scope < Validation Scope.
//!
//! ## Vulnerability Pattern
//!
//! ```rust,ignore
//! if condition {
//!     require!(amount > 0); // Validated at Scope 1
//! }
//! // Usage at Scope 0
//! token::transfer(ctx, amount)?; // BUG: Usage Scope (0) < Validation Scope (1)
//! ```

use std::collections::HashMap;
use syn::{visit::{self, Visit}, Expr, ExprCall, ExprIf, ExprBlock, ExprLoop, ExprForLoop, ExprWhile};

/// Tracks scope depth and variable states.
#[derive(Debug, Default)]
pub struct ScopeTracker {
    /// Current scope depth
    current_depth: usize,
    /// Variables validated at each scope: var_name -> min_scope_depth
    /// We verify "min" because if it's validated at scope 0, it's safe at scope 1.
    /// But here we track *where* the validation happened.
    validated_at: HashMap<String, usize>,
    /// Usages found: (var_name, line, usage_scope)
    usages: Vec<(String, usize, usize)>,
    /// Helper to track line numbers from AST spans (simplified)
    current_line: usize,
}

impl ScopeTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn analyze(&mut self, file: &syn::File) {
        self.visit_file(file);
    }

    pub fn find_scope_violations(&self) -> Vec<(String, usize, String)> {
        let mut violations = Vec::new();

        for (var, line, usage_scope) in &self.usages {
            if let Some(&validation_scope) = self.validated_at.get(var) {
                // If validation happened at a deeper (inner) scope than usage
                // E.g. Validated inside if (scope 1), used outside (scope 0)
                if validation_scope > *usage_scope {
                    violations.push((
                        var.clone(),
                        *line,
                        format!(
                            "Variable '{}' checked inside a block (depth {}) but used outside (depth {}). The check does not protect this usage.",
                            var, validation_scope, usage_scope
                        ),
                    ));
                }
            }
        }
        violations
    }

    fn record_validation(&mut self, var: &str) {
        // We record the *current* depth as the validation scope.
        // If it was already validated at a *lower* depth (broader scope), keep that.
        // If it was validated at higher depth, update to lower logic?
        // Actually, we want to know if it's ONLY validated at high depth.
        // So we store the LOWEST depth where we've seen a validation?
        // No, wait.
        // If I validate at Scope 0, I am safe at Scope 0 and 1.
        // If I validate at Scope 1, I am safe at Scope 1, but unsafe at Scope 0.
        // So validation_scope = current_depth.
        // If we see multiple validations, we should probably take the 'best' one (min depth).
        
        let entry = self.validated_at.entry(var.to_string()).or_insert(self.current_depth);
        if self.current_depth < *entry {
            *entry = self.current_depth;
        }
    }

    fn record_usage(&mut self, var: &str, line: usize) {
        self.usages.push((var.to_string(), line, self.current_depth));
    }
}

impl<'ast> Visit<'ast> for ScopeTracker {
    fn visit_expr_if(&mut self, i: &ExprIf) {
        // Condition is evaluated in current scope
        self.visit_expr(&i.cond);
        
        // Then block increases scope
        self.current_depth += 1;
        self.visit_block(&i.then_branch);
        self.current_depth -= 1;
        
        // Else branch also increases scope (separate branch)
        if let Some((_, else_branch)) = &i.else_branch {
            self.current_depth += 1;
            self.visit_expr(else_branch);
            self.current_depth -= 1;
        }
    }

    fn visit_expr_loop(&mut self, i: &ExprLoop) {
        self.current_depth += 1;
        self.visit_block(&i.body);
        self.current_depth -= 1;
    }

    fn visit_expr_for_loop(&mut self, i: &ExprForLoop) {
        self.visit_expr(&i.expr); // iterator expr at outer scope
        
        self.current_depth += 1;
        self.visit_block(&i.body);
        self.current_depth -= 1;
    }

    fn visit_expr_while(&mut self, i: &ExprWhile) {
        self.visit_expr(&i.cond);
        
        self.current_depth += 1;
        self.visit_block(&i.body);
        self.current_depth -= 1;
    }

    fn visit_expr_block(&mut self, i: &ExprBlock) {
        self.current_depth += 1;
        for stmt in &i.block.stmts {
            self.visit_stmt(stmt);
        }
        self.current_depth -= 1;
    }

    fn visit_macro(&mut self, mac: &syn::Macro) {
        // Primitive way to detect macro line numbers roughly
        // In a real implementation we'd use span, but we don't have span info easily in this context
        // without proc_macro2::Span which is dummy in syn locally unless enabled features.
        // We'll rely on our best guess.
        
        let path_str = quote::quote!(#mac.path).to_string();
        
        if path_str.contains("require") || path_str.contains("assert") {
            // Extract tokens to find variables
            let tokens = mac.tokens.to_string();
            // Simple heuristic to extract vars
            extract_vars_from_expr_str(&tokens, |var| self.record_validation(var));
        }
    }

    fn visit_expr_call(&mut self, i: &ExprCall) {
        let func_name = quote::quote!(#i.func).to_string();
        
        // Sensitive sink detection
        if func_name.contains("transfer") || func_name.contains("invoke") || func_name.contains("burn") {
            // Check args
            for arg in &i.args {
                let arg_str = quote::quote!(#arg).to_string();
                extract_vars_from_expr_str(&arg_str, |var| {
                   // Using line 0 as placeholder since we don't have spans easily
                   // In integration we'll try to map this better
                   self.record_usage(var, 0); 
                });
            }
        }
        
        // Also check CheckedMath that acts as validation? 
        // checked_mul etc returns Option, usually handled. 
        // If it's `val.checked_mul(x).ok_or(...)`, the `val` isn't validated, the *result* is.
        
        // Recurse
        visit::visit_expr_call(self, i);
    }
    
    // Track usage in method calls like .borrow_mut()
    fn visit_expr_method_call(&mut self, i: &syn::ExprMethodCall) {
        let method = i.method.to_string();
        if method == "borrow_mut" || method == "try_borrow_mut" {
            let receiver = quote::quote!(#i.receiver).to_string();
            extract_vars_from_expr_str(&receiver, |var| self.record_usage(var, 0));
        }
        visit::visit_expr_method_call(self, i);
    }
}

// Helper to extract simple variable names from an expression string
fn extract_vars_from_expr_str<F>(expr: &str, mut cb: F) 
where F: FnMut(&str) {
    let parts: Vec<&str> = expr.split(|c: char| !c.is_alphanumeric() && c != '_').collect();
    for part in parts {
        if !part.is_empty() 
           && part.chars().next().unwrap().is_alphabetic() 
           && part != "ctx" && part != "accounts" && part != "key" && part != "unwrap"
           && part != "require" && part != "true" && part != "false"
        {
            cb(part);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn test_scope_violation() {
        let mut tracker = ScopeTracker::new();
        
        let code: syn::File = parse_quote! {
            fn test() {
                if condition {
                    require!(amount > 0);
                }
                
                token::transfer(ctx, amount);
            }
        };
        
        tracker.analyze(&code);
        let violations = tracker.find_scope_violations();
        
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "amount");
        assert!(violations[0].2.contains("inside a block"));
    }

    #[test]
    fn test_safe_scope() {
        let mut tracker = ScopeTracker::new();
        
        let code: syn::File = parse_quote! {
            fn test() {
                require!(amount > 0);
                
                if condition {
                    token::transfer(ctx, amount);
                }
            }
        };
        
        tracker.analyze(&code);
        let violations = tracker.find_scope_violations();
        
        assert!(violations.is_empty());
    }
}
