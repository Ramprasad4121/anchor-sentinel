//! # Global Program Context
//!
//! @title Cross-File Program Understanding
//! @author Ramprasad
//!
//! Provides two-pass analysis with a knowledge graph that indexes the entire
//! codebase before running detectors.
//!
//! ## Two-Pass Strategy
//!
//! - **Pass 1 (Indexing)**: Scan entire codebase, build knowledge graph
//!   - Map structs to fields/types
//!   - Identify #[account] structs
//!   - Resolve constant values
//!
//! - **Pass 2 (Detection)**: Run detectors with global context injected

use std::collections::HashMap;
use std::path::Path;

/// Information about a struct definition.
#[derive(Debug, Clone, Default)]
pub struct StructInfo {
    /// Name of the struct
    pub name: String,
    /// File where the struct is defined
    pub file: String,
    /// Field definitions: name -> type
    pub fields: HashMap<String, String>,
    /// Whether this is an #[account] struct
    pub is_account: bool,
    /// Whether this is an #[derive(Accounts)] struct
    pub is_accounts_context: bool,
}

/// Information about a constant.
#[derive(Debug, Clone)]
pub struct ConstantInfo {
    /// Name of the constant
    pub name: String,
    /// Resolved value (if determinable)
    pub value: Option<i128>,
    /// String representation
    pub value_str: String,
}

/// Information about an instruction function.
#[derive(Debug, Clone, Default)]
pub struct InstructionInfo {
    /// Function name
    pub name: String,
    /// File path
    pub file: String,
    /// Arguments: name -> type
    pub args: HashMap<String, String>,
    /// The Context<T> type parameter
    pub context_type: Option<String>,
    /// Line number
    pub line: usize,
}

/// Global program context built from indexing the codebase.
#[derive(Debug, Default)]
pub struct ProgramContext {
    /// All struct definitions: fully qualified name -> info
    pub structs: HashMap<String, StructInfo>,
    /// All #[account] structs
    pub accounts: HashMap<String, StructInfo>,
    /// All constants: name -> info
    pub constants: HashMap<String, ConstantInfo>,
    /// All instruction functions
    pub instructions: Vec<InstructionInfo>,
    /// File contents cache: path -> source
    file_cache: HashMap<String, String>,
}

impl ProgramContext {
    /// Creates a new empty program context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Indexes a source file and adds its information to the context.
    pub fn index_file(&mut self, path: &str, source: &str) {
        self.file_cache.insert(path.to_string(), source.to_string());
        
        // Parse with syn
        if let Ok(syntax) = syn::parse_file(source) {
            self.extract_from_file(path, &syntax);
        }
    }

    /// Extracts struct, constant, and function info from a parsed file.
    fn extract_from_file(&mut self, path: &str, file: &syn::File) {
        use syn::{Item, ItemStruct, ItemConst, ItemFn, Fields};
        
        for item in &file.items {
            match item {
                Item::Struct(s) => {
                    self.index_struct(path, s);
                }
                Item::Const(c) => {
                    self.index_constant(c);
                }
                Item::Fn(f) => {
                    self.index_function(path, f);
                }
                Item::Mod(m) => {
                    // Recursively index inline modules
                    if let Some((_, items)) = &m.content {
                        for item in items {
                            if let Item::Struct(s) = item {
                                self.index_struct(path, s);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn index_struct(&mut self, path: &str, s: &syn::ItemStruct) {
        let name = s.ident.to_string();
        let mut info = StructInfo {
            name: name.clone(),
            file: path.to_string(),
            fields: HashMap::new(),
            is_account: false,
            is_accounts_context: false,
        };

        // Check attributes for #[account] or #[derive(Accounts)]
        for attr in &s.attrs {
            let attr_str = quote::quote!(#attr).to_string();
            if attr_str.contains("account") {
                info.is_account = true;
            }
            if attr_str.contains("derive") && attr_str.contains("Accounts") {
                info.is_accounts_context = true;
            }
        }

        // Extract fields
        if let syn::Fields::Named(fields) = &s.fields {
            for field in &fields.named {
                if let Some(ident) = &field.ident {
                    let ty = quote::quote!(#field.ty).to_string();
                    info.fields.insert(ident.to_string(), ty);
                }
            }
        }

        if info.is_account {
            self.accounts.insert(name.clone(), info.clone());
        }
        self.structs.insert(name, info);
    }

    fn index_constant(&mut self, c: &syn::ItemConst) {
        let name = c.ident.to_string();
        let value_str = quote::quote!(#c.expr).to_string();
        
        // Try to parse numeric value from the expression
        // Handle cases like "1000", "1_000", "(1000 as u64)", etc.
        let value = self.extract_numeric_value(&c.expr);

        self.constants.insert(name.clone(), ConstantInfo {
            name,
            value,
            value_str,
        });
    }
    
    /// Extracts a numeric value from an expression if possible.
    fn extract_numeric_value(&self, expr: &syn::Expr) -> Option<i128> {
        match expr {
            syn::Expr::Lit(lit) => {
                if let syn::Lit::Int(int_lit) = &lit.lit {
                    int_lit.base10_parse::<i128>().ok()
                } else {
                    None
                }
            }
            syn::Expr::Cast(cast) => {
                // Handle (value as Type) patterns
                self.extract_numeric_value(&cast.expr)
            }
            syn::Expr::Paren(paren) => {
                // Handle (value) patterns
                self.extract_numeric_value(&paren.expr)
            }
            syn::Expr::Unary(unary) => {
                // Handle negative numbers
                if matches!(unary.op, syn::UnOp::Neg(_)) {
                    self.extract_numeric_value(&unary.expr).map(|v| -v)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn index_function(&mut self, path: &str, f: &syn::ItemFn) {
        // Check if this looks like an instruction (has Context<T> parameter)
        let mut info = InstructionInfo {
            name: f.sig.ident.to_string(),
            file: path.to_string(),
            args: HashMap::new(),
            context_type: None,
            line: 0,
        };

        for arg in &f.sig.inputs {
            if let syn::FnArg::Typed(pat_type) = arg {
                if let syn::Pat::Ident(ident) = &*pat_type.pat {
                    let arg_name = ident.ident.to_string();
                    let arg_type = quote::quote!(#pat_type.ty).to_string();
                    
                    // Check for Context<T>
                    if arg_type.contains("Context") {
                        if let Some(start) = arg_type.find('<') {
                            if let Some(end) = arg_type.rfind('>') {
                                info.context_type = Some(arg_type[start+1..end].trim().to_string());
                            }
                        }
                    }
                    
                    info.args.insert(arg_name, arg_type);
                }
            }
        }

        // Only add if it looks like an instruction
        if info.context_type.is_some() {
            self.instructions.push(info);
        }
    }

    /// Resolves a struct by name.
    pub fn resolve_struct(&self, name: &str) -> Option<&StructInfo> {
        self.structs.get(name)
    }

    /// Gets the type of an account field.
    pub fn get_account_field_type(&self, struct_name: &str, field_name: &str) -> Option<String> {
        self.structs.get(struct_name)
            .and_then(|s| s.fields.get(field_name))
            .cloned()
    }

    /// Resolves a constant to its value.
    pub fn resolve_constant(&self, name: &str) -> Option<i128> {
        self.constants.get(name).and_then(|c| c.value)
    }

    /// Gets all instruction functions.
    pub fn get_instructions(&self) -> &[InstructionInfo] {
        &self.instructions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_index_struct() {
        let mut ctx = ProgramContext::new();
        let source = r#"
            #[account]
            pub struct Vault {
                pub owner: Pubkey,
                pub balance: u64,
            }
        "#;
        
        ctx.index_file("test.rs", source);
        
        assert!(ctx.accounts.contains_key("Vault"));
        let vault = ctx.structs.get("Vault").unwrap();
        assert!(vault.is_account);
        assert!(vault.fields.contains_key("owner"));
    }

    #[test]
    fn test_index_constant() {
        let mut ctx = ProgramContext::new();
        let source = r#"
            pub const MAX_USERS: u64 = 1000;
            pub const FEE_BPS: u64 = 30;
        "#;
        
        ctx.index_file("test.rs", source);
        
        assert_eq!(ctx.resolve_constant("MAX_USERS"), Some(1000));
        assert_eq!(ctx.resolve_constant("FEE_BPS"), Some(30));
    }
}
