//! # Instruction Handler Parsing
//!
//! @title Instruction Handler Analyzer
//! @author Ramprasad
//!
//! This module extracts instruction handler functions from parsed AST and
//! analyzes their contents for arithmetic operations and CPI calls.
//!
//! ## Key Functions
//!
//! - [`extract_instruction_handlers`] - Extract all instruction handlers from AST

use super::*;
use syn::visit::Visit;
use syn::{Attribute, BinOp, Expr, ExprBinary, ExprCall, ExprMethodCall, File, ItemFn, Signature};

/// Extracts all instruction handlers from the AST.
///
/// Identifies functions that take a `Context<T>` parameter, which is the
/// standard signature for Anchor instruction handlers.
///
/// # Arguments
///
/// * `ast` - Parsed Rust syntax tree
///
/// # Returns
///
/// A vector of [`InstructionHandler`] instances.
pub fn extract_instruction_handlers(ast: &File) -> Vec<InstructionHandler> {
    let mut visitor = InstructionVisitor::new();
    visitor.visit_file(ast);
    visitor.handlers
}

/// AST visitor for instruction handler functions.
struct InstructionVisitor {
    handlers: Vec<InstructionHandler>,
}

impl InstructionVisitor {
    /// Creates a new visitor instance.
    fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    /// Checks if a function has the `#[instruction]` attribute.
    ///
    /// # Arguments
    ///
    /// * `attrs` - Slice of attributes on the function
    ///
    /// # Returns
    ///
    /// `true` if the function has an instruction attribute.
    #[allow(dead_code)]
    fn is_instruction_handler(&self, attrs: &[Attribute]) -> bool {
        attrs.iter().any(|a| a.path().is_ident("instruction"))
    }

    /// Extracts the accounts type from a Context<T> parameter.
    ///
    /// Searches the function signature for a parameter with type `Context<T>`
    /// and extracts the generic parameter `T`.
    ///
    /// # Arguments
    ///
    /// * `sig` - The function signature
    ///
    /// # Returns
    ///
    /// The accounts type name if found, `None` otherwise.
    fn extract_accounts_type(&self, sig: &Signature) -> Option<String> {
        for input in &sig.inputs {
            if let syn::FnArg::Typed(pat_type) = input {
                let ty_str = quote::quote!(#pat_type.ty).to_string();
                if ty_str.contains("Context") {
                    if let syn::Type::Path(type_path) = &*pat_type.ty {
                        for seg in &type_path.path.segments {
                            if seg.ident == "Context" {
                                if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                                    for arg in &args.args {
                                        if let syn::GenericArgument::Type(inner) = arg {
                                            return Some(quote::quote!(#inner).to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Extracts instruction arguments from the function signature.
    ///
    /// Collects all typed parameters except for the Context parameter.
    ///
    /// # Arguments
    ///
    /// * `sig` - The function signature
    ///
    /// # Returns
    ///
    /// A vector of [`InstructionArg`] instances.
    fn extract_args(&self, sig: &Signature) -> Vec<InstructionArg> {
        let mut args = Vec::new();

        for input in &sig.inputs {
            if let syn::FnArg::Typed(pat_type) = input {
                let ty_str = quote::quote!(#pat_type.ty).to_string();

                // Skip Context parameter
                if ty_str.contains("Context") {
                    continue;
                }

                if let syn::Pat::Ident(pat_ident) = &*pat_type.pat {
                    args.push(InstructionArg {
                        name: pat_ident.ident.to_string(),
                        ty: ty_str.replace(' ', ""),
                    });
                }
            }
        }

        args
    }
}

impl<'ast> Visit<'ast> for InstructionVisitor {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let accounts_type = self.extract_accounts_type(&node.sig);

        if accounts_type.is_some() {
            let mut analyzer = FunctionBodyAnalyzer::new();
            analyzer.visit_block(&node.block);

            self.handlers.push(InstructionHandler {
                name: node.sig.ident.to_string(),
                accounts_type: accounts_type.unwrap_or_default(),
                args: self.extract_args(&node.sig),
                start_line: 0,
                end_line: 0,
                arithmetic_ops: analyzer.arithmetic_ops,
                cpi_calls: analyzer.cpi_calls,
            });
        }

        syn::visit::visit_item_fn(self, node);
    }
}

/// Analyzer for function body contents.
///
/// Extracts arithmetic operations and CPI calls from instruction handler bodies.
struct FunctionBodyAnalyzer {
    arithmetic_ops: Vec<ArithmeticOp>,
    cpi_calls: Vec<CpiCall>,
}

impl FunctionBodyAnalyzer {
    /// Creates a new analyzer instance.
    fn new() -> Self {
        Self {
            arithmetic_ops: Vec::new(),
            cpi_calls: Vec::new(),
        }
    }

    /// Checks if a method name represents checked arithmetic.
    ///
    /// # Arguments
    ///
    /// * `method_name` - The method name to check
    ///
    /// # Returns
    ///
    /// `true` if the method is a checked or saturating arithmetic operation.
    fn is_checked_method(&self, method_name: &str) -> bool {
        matches!(
            method_name,
            "checked_add"
                | "checked_sub"
                | "checked_mul"
                | "checked_div"
                | "saturating_add"
                | "saturating_sub"
                | "saturating_mul"
        )
    }
}

impl<'ast> Visit<'ast> for FunctionBodyAnalyzer {
    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        let operation = match &node.op {
            BinOp::Add(_) => Some("add"),
            BinOp::Sub(_) => Some("sub"),
            BinOp::Mul(_) => Some("mul"),
            BinOp::Div(_) => Some("div"),
            _ => None,
        };

        if let Some(op) = operation {
            self.arithmetic_ops.push(ArithmeticOp {
                operation: op.to_string(),
                is_checked: false,
                line: 0,
                expression: quote::quote!(#node).to_string(),
            });
        }

        syn::visit::visit_expr_binary(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method_name = node.method.to_string();

        if self.is_checked_method(&method_name) {
            let op_type = if method_name.contains("add") {
                "add"
            } else if method_name.contains("sub") {
                "sub"
            } else if method_name.contains("mul") {
                "mul"
            } else {
                "div"
            };

            self.arithmetic_ops.push(ArithmeticOp {
                operation: op_type.to_string(),
                is_checked: true,
                line: 0,
                expression: quote::quote!(#node).to_string(),
            });
        }

        if method_name == "invoke" || method_name == "invoke_signed" {
            self.cpi_calls.push(CpiCall {
                program: "Unknown".to_string(),
                is_program_hardcoded: false,
                line: 0,
            });
        }

        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(path) = &*node.func {
            let path_str = quote::quote!(#path).to_string();
            if path_str.contains("invoke") {
                self.cpi_calls.push(CpiCall {
                    program: "Unknown".to_string(),
                    is_program_hardcoded: false,
                    line: 0,
                });
            }
        }

        syn::visit::visit_expr_call(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_instruction_handler() {
        let source = r#"
            pub fn initialize(ctx: Context<Initialize>, amount: u64) -> Result<()> {
                let total = ctx.accounts.balance + amount;
                Ok(())
            }
        "#;

        let ast = syn::parse_file(source).unwrap();
        let handlers = extract_instruction_handlers(&ast);

        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0].name, "initialize");
        assert_eq!(handlers[0].accounts_type, "Initialize");
        assert_eq!(handlers[0].args.len(), 1);
        assert_eq!(handlers[0].args[0].name, "amount");
    }

    #[test]
    fn test_detect_arithmetic_ops() {
        let source = r#"
            pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
                let unchecked = a + b;
                let checked = a.checked_add(b).unwrap();
                Ok(())
            }
        "#;

        let ast = syn::parse_file(source).unwrap();
        let handlers = extract_instruction_handlers(&ast);

        assert_eq!(handlers.len(), 1);

        let unchecked_count = handlers[0]
            .arithmetic_ops
            .iter()
            .filter(|op| !op.is_checked)
            .count();
        let checked_count = handlers[0]
            .arithmetic_ops
            .iter()
            .filter(|op| op.is_checked)
            .count();

        assert!(unchecked_count >= 1);
        assert!(checked_count >= 1);
    }
}
