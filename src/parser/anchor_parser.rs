//! # Anchor-Specific AST Parsing
//!
//! @title Anchor Account Parser
//! @author Ramprasad
//!
//! This module provides parsing functionality specific to the Anchor framework,
//! extracting account structures, constraints, and state definitions from
//! parsed Rust AST.
//!
//! ## Key Functions
//!
//! - [`extract_account_structs`] - Extract `#[derive(Accounts)]` structs
//! - [`extract_state_accounts`] - Extract `#[account]` state definitions
//! - [`extract_error_codes`] - Extract `#[error_code]` enum variants

use super::*;
use syn::visit::Visit;
use syn::{Attribute, Field, Fields, File, GenericArgument, ItemStruct, PathArguments, Type};

/// Extracts all account structs from the AST.
///
/// Searches for structs annotated with `#[derive(Accounts)]` and parses
/// their fields and constraints.
///
/// # Arguments
///
/// * `ast` - Parsed Rust syntax tree
///
/// # Returns
///
/// A vector of [`AccountStruct`] instances representing all found account structs.
pub fn extract_account_structs(ast: &File) -> Vec<AccountStruct> {
    let mut visitor = AccountStructVisitor::new();
    visitor.visit_file(ast);
    visitor.accounts
}

/// Extracts state account definitions from the AST.
///
/// Searches for structs annotated with `#[account]` which define
/// program state structures.
///
/// # Arguments
///
/// * `ast` - Parsed Rust syntax tree
///
/// # Returns
///
/// A vector of [`StateAccount`] instances.
pub fn extract_state_accounts(ast: &File) -> Vec<StateAccount> {
    let mut visitor = StateAccountVisitor::new();
    visitor.visit_file(ast);
    visitor.states
}

/// Extracts error codes from the AST.
///
/// Searches for enums annotated with `#[error_code]` and extracts
/// their variants and messages.
///
/// # Arguments
///
/// * `ast` - Parsed Rust syntax tree
///
/// # Returns
///
/// A vector of [`ErrorCode`] instances.
pub fn extract_error_codes(ast: &File) -> Vec<ErrorCode> {
    let mut visitor = ErrorCodeVisitor::new();
    visitor.visit_file(ast);
    visitor.errors
}

/// AST visitor for extracting account structs.
struct AccountStructVisitor {
    accounts: Vec<AccountStruct>,
}

impl AccountStructVisitor {
    /// Creates a new visitor instance.
    fn new() -> Self {
        Self {
            accounts: Vec::new(),
        }
    }

    /// Checks if a struct has the `#[derive(Accounts)]` attribute.
    ///
    /// # Arguments
    ///
    /// * `attrs` - Slice of attributes on the struct
    ///
    /// # Returns
    ///
    /// `true` if the struct derives `Accounts`, `false` otherwise.
    fn has_accounts_derive(&self, attrs: &[Attribute]) -> bool {
        attrs.iter().any(|attr| {
            if attr.path().is_ident("derive") {
                if let Ok(meta) = attr.meta.require_list() {
                    let tokens = meta.tokens.to_string();
                    return tokens.contains("Accounts");
                }
            }
            false
        })
    }

    /// Parses an account field from the AST.
    ///
    /// Extracts the field name, type, constraints, and flags.
    ///
    /// # Arguments
    ///
    /// * `field` - The struct field to parse
    ///
    /// # Returns
    ///
    /// An [`AccountField`] representing the parsed field.
    fn parse_account_field(&self, field: &Field) -> AccountField {
        let name = field
            .ident
            .as_ref()
            .map(|i| i.to_string())
            .unwrap_or_default();
        let ty = parse_account_type(&field.ty);
        let constraints = parse_constraints(&field.attrs);

        let is_mutable = constraints
            .iter()
            .any(|c| matches!(c.constraint_type, ConstraintType::Mut));
        let is_signer = constraints
            .iter()
            .any(|c| matches!(c.constraint_type, ConstraintType::Signer))
            || matches!(ty, AccountType::Signer);
        let is_init = constraints.iter().any(|c| {
            matches!(
                c.constraint_type,
                ConstraintType::Init | ConstraintType::InitIfNeeded
            )
        });

        AccountField {
            name,
            ty,
            constraints,
            is_mutable,
            is_signer,
            is_init,
            line: 0,
        }
    }
}

impl<'ast> Visit<'ast> for AccountStructVisitor {
    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        if self.has_accounts_derive(&node.attrs) {
            let fields = match &node.fields {
                Fields::Named(named) => named
                    .named
                    .iter()
                    .map(|f| self.parse_account_field(f))
                    .collect(),
                _ => Vec::new(),
            };

            self.accounts.push(AccountStruct {
                name: node.ident.to_string(),
                fields,
                start_line: 0,
                end_line: 0,
            });
        }

        syn::visit::visit_item_struct(self, node);
    }
}

/// Parses the account type from a `syn::Type`.
///
/// Categorizes the type into one of the known Anchor account types.
///
/// # Arguments
///
/// * `ty` - The type to parse
///
/// # Returns
///
/// An [`AccountType`] classification.
fn parse_account_type(ty: &Type) -> AccountType {
    match ty {
        Type::Path(type_path) => {
            let segments: Vec<_> = type_path.path.segments.iter().collect();
            if let Some(last) = segments.last() {
                let ident = last.ident.to_string();

                match ident.as_str() {
                    "AccountInfo" => AccountType::AccountInfo,
                    "Signer" => AccountType::Signer,
                    "SystemProgram" => AccountType::SystemProgram,
                    "UncheckedAccount" => AccountType::UncheckedAccount,
                    "SystemAccount" => AccountType::SystemAccount,
                    "Account" => {
                        if let PathArguments::AngleBracketed(args) = &last.arguments {
                            for arg in &args.args {
                                if let GenericArgument::Type(inner_ty) = arg {
                                    let inner = type_to_string(inner_ty);
                                    if inner != "'info" {
                                        return AccountType::Account(inner);
                                    }
                                }
                            }
                        }
                        AccountType::Account("Unknown".to_string())
                    }
                    "Program" => {
                        if let PathArguments::AngleBracketed(args) = &last.arguments {
                            for arg in &args.args {
                                if let GenericArgument::Type(inner_ty) = arg {
                                    let inner = type_to_string(inner_ty);
                                    if inner != "'info" {
                                        return AccountType::Program(inner);
                                    }
                                }
                            }
                        }
                        AccountType::Program("Unknown".to_string())
                    }
                    _ => AccountType::Unknown(ident),
                }
            } else {
                AccountType::Unknown(quote::quote!(#ty).to_string())
            }
        }
        _ => AccountType::Unknown(quote::quote!(#ty).to_string()),
    }
}

/// Converts a `Type` to its string representation.
///
/// # Arguments
///
/// * `ty` - The type to convert
///
/// # Returns
///
/// The type as a string with whitespace removed.
fn type_to_string(ty: &Type) -> String {
    quote::quote!(#ty).to_string().replace(' ', "")
}

/// Parses constraints from field attributes.
///
/// Extracts constraint information from `#[account(...)]` attributes.
///
/// # Arguments
///
/// * `attrs` - Slice of attributes on the field
///
/// # Returns
///
/// A vector of parsed [`Constraint`] instances.
fn parse_constraints(attrs: &[Attribute]) -> Vec<Constraint> {
    let mut constraints = Vec::new();

    for attr in attrs {
        if attr.path().is_ident("account") {
            if let Ok(meta) = attr.meta.require_list() {
                let tokens = meta.tokens.to_string();

                for constraint_str in split_constraints(&tokens) {
                    if let Some(constraint) = parse_single_constraint(&constraint_str) {
                        constraints.push(constraint);
                    }
                }
            }
        }
    }

    constraints
}

/// Splits a constraint string into individual constraints.
///
/// Handles nested parentheses and brackets correctly.
///
/// # Arguments
///
/// * `s` - The constraint string to split
///
/// # Returns
///
/// A vector of individual constraint strings.
fn split_constraints(s: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut paren_depth = 0;

    for ch in s.chars() {
        match ch {
            '(' | '[' => {
                paren_depth += 1;
                current.push(ch);
            }
            ')' | ']' => {
                paren_depth -= 1;
                current.push(ch);
            }
            ',' if paren_depth == 0 => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    result.push(trimmed);
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        result.push(trimmed);
    }

    result
}

/// Parses a single constraint string into a Constraint struct.
///
/// # Arguments
///
/// * `s` - The constraint string to parse
///
/// # Returns
///
/// A [`Constraint`] if parsing succeeds, `None` otherwise.
fn parse_single_constraint(s: &str) -> Option<Constraint> {
    let s = s.trim();

    let constraint_type = if s == "init" {
        ConstraintType::Init
    } else if s == "init_if_needed" {
        ConstraintType::InitIfNeeded
    } else if s == "mut" {
        ConstraintType::Mut
    } else if s == "signer" {
        ConstraintType::Signer
    } else if s.starts_with("has_one") {
        let inner = extract_inner(s, "has_one");
        ConstraintType::HasOne(inner)
    } else if s.starts_with("seeds") {
        let inner = extract_inner(s, "seeds");
        let seeds = parse_seeds(&inner);
        ConstraintType::Seeds(seeds)
    } else if s == "bump" || s.starts_with("bump") {
        ConstraintType::Bump
    } else if s.starts_with("payer") {
        let inner = extract_inner(s, "payer");
        ConstraintType::Payer(inner)
    } else if s.starts_with("space") {
        let inner = extract_inner(s, "space");
        ConstraintType::Space(inner)
    } else if s.starts_with("owner") {
        let inner = extract_inner(s, "owner");
        ConstraintType::Owner(inner)
    } else if s.starts_with("constraint") {
        let inner = extract_inner(s, "constraint");
        ConstraintType::Constraint(inner)
    } else if s.starts_with("address") {
        let inner = extract_inner(s, "address");
        ConstraintType::Address(inner)
    } else if s.starts_with("close") {
        let inner = extract_inner(s, "close");
        ConstraintType::Close(inner)
    } else {
        ConstraintType::Unknown(s.to_string())
    };

    Some(Constraint {
        constraint_type,
        raw: s.to_string(),
        line: 0,
    })
}

/// Extracts the inner value from a constraint expression.
///
/// For example, extracts "authority" from "has_one = authority".
///
/// # Arguments
///
/// * `s` - The full constraint string
/// * `prefix` - The constraint prefix to strip
///
/// # Returns
///
/// The extracted inner value.
fn extract_inner(s: &str, prefix: &str) -> String {
    s.strip_prefix(prefix)
        .unwrap_or("")
        .trim()
        .trim_start_matches('=')
        .trim()
        .to_string()
}

/// Parses seeds from a seeds constraint expression.
///
/// # Arguments
///
/// * `s` - The seeds expression (including brackets)
///
/// # Returns
///
/// A vector of individual seed expressions.
fn parse_seeds(s: &str) -> Vec<String> {
    let inner = s.trim_start_matches('[').trim_end_matches(']');
    inner
        .split(',')
        .map(|seed| seed.trim().to_string())
        .filter(|seed| !seed.is_empty())
        .collect()
}

/// AST visitor for state account definitions.
struct StateAccountVisitor {
    states: Vec<StateAccount>,
}

impl StateAccountVisitor {
    fn new() -> Self {
        Self { states: Vec::new() }
    }

    /// Checks if a struct has the `#[account]` attribute.
    fn has_account_attr(&self, attrs: &[Attribute]) -> bool {
        attrs.iter().any(|attr| attr.path().is_ident("account"))
    }
}

impl<'ast> Visit<'ast> for StateAccountVisitor {
    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        if self.has_account_attr(&node.attrs) {
            let fields = match &node.fields {
                Fields::Named(named) => named
                    .named
                    .iter()
                    .filter_map(|f| {
                        let name = f.ident.as_ref()?.to_string();
                        let ty = type_to_string(&f.ty);
                        Some((name, ty))
                    })
                    .collect(),
                _ => Vec::new(),
            };

            self.states.push(StateAccount {
                name: node.ident.to_string(),
                fields,
                has_discriminator: true,
                line: 0,
            });
        }

        syn::visit::visit_item_struct(self, node);
    }
}

/// AST visitor for error code enums.
struct ErrorCodeVisitor {
    errors: Vec<ErrorCode>,
}

impl ErrorCodeVisitor {
    fn new() -> Self {
        Self { errors: Vec::new() }
    }
}

impl<'ast> Visit<'ast> for ErrorCodeVisitor {
    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        let has_error_code = node.attrs.iter().any(|a| a.path().is_ident("error_code"));

        if has_error_code {
            for variant in &node.variants {
                let code: Option<u32> = None;
                let mut message = None;

                for attr in &variant.attrs {
                    if attr.path().is_ident("msg") {
                        if let Ok(meta) = attr.meta.require_list() {
                            message = Some(meta.tokens.to_string().trim_matches('"').to_string());
                        }
                    }
                }

                self.errors.push(ErrorCode {
                    name: variant.ident.to_string(),
                    code,
                    message,
                });
            }
        }

        syn::visit::visit_item_enum(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_account_struct() {
        let source = r#"
            use anchor_lang::prelude::*;
            
            #[derive(Accounts)]
            pub struct Initialize<'info> {
                #[account(init, payer = user, space = 8 + 32)]
                pub my_account: Account<'info, MyState>,
                #[account(mut)]
                pub user: Signer<'info>,
                pub system_program: Program<'info, System>,
            }
        "#;

        let ast = syn::parse_file(source).unwrap();
        let accounts = extract_account_structs(&ast);

        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].name, "Initialize");
        assert_eq!(accounts[0].fields.len(), 3);
    }

    #[test]
    fn test_split_constraints() {
        let input =
            "init, payer = user, space = 8 + 32, seeds = [b\"seed\", user.key().as_ref()]";
        let result = split_constraints(input);

        assert_eq!(result.len(), 4);
        assert_eq!(result[0], "init");
        assert!(result[3].contains("seeds"));
    }
}
