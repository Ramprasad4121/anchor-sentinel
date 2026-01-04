//! # Parser Module
//!
//! @title AST Parser for Anchor Programs
//! @author Ramprasad
//!
//! This module provides AST parsing utilities for analyzing Anchor smart contracts.
//! It uses the `syn` crate to parse Rust source code and extract relevant structures
//! for vulnerability analysis.
//!
//! ## Submodules
//!
//! - [`anchor_parser`] - Anchor-specific parsing for account structs and constraints
//! - [`instruction_parser`] - Instruction handler extraction and analysis
//!
//! ## Key Types
//!
//! - [`AnalysisContext`] - Complete context for analyzing a parsed Anchor program
//! - [`AccountStruct`] - Represents a `#[derive(Accounts)]` struct
//! - [`AccountField`] - Individual field within an account struct
//! - [`InstructionHandler`] - Parsed instruction handler function

mod anchor_parser;
mod instruction_parser;

pub use anchor_parser::*;
pub use instruction_parser::*;

use anyhow::Result;
use std::path::Path;
use syn::File;

/// Complete analysis context for a parsed Anchor program.
///
/// This structure contains all parsed information needed for vulnerability
/// detection, including the raw source code, AST, and extracted Anchor-specific
/// structures.
///
/// # Example
///
/// ```rust,ignore
/// let context = AnalysisContext::from_source("program.rs", source_code)?;
/// for account in &context.accounts {
///     println!("Found account struct: {}", account.name);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AnalysisContext {
    /// Absolute or relative path to the source file.
    pub file_path: String,

    /// Raw source code content.
    pub source_code: String,

    /// Parsed abstract syntax tree.
    pub ast: File,

    /// Extracted Anchor account structures.
    ///
    /// Contains all structs marked with `#[derive(Accounts)]`.
    pub accounts: Vec<AccountStruct>,

    /// Extracted instruction handler functions.
    ///
    /// Functions that take a `Context<T>` parameter.
    pub instructions: Vec<InstructionHandler>,

    /// Program state account definitions.
    ///
    /// Structs marked with the `#[account]` attribute.
    pub state_accounts: Vec<StateAccount>,

    /// Error code definitions from `#[error_code]` enums.
    pub error_codes: Vec<ErrorCode>,

    /// Program name extracted from `#[program] pub mod name` or Anchor.toml.
    pub program_name: Option<String>,

    /// Program ID extracted from `declare_id!("...")`.
    pub program_id: Option<String>,

    /// Global program context for cross-file analysis.
    pub program_context: Option<std::sync::Arc<crate::analysis::ProgramContext>>,
}

impl AnalysisContext {
    /// Creates a new analysis context from source code.
    ///
    /// Parses the provided source code and extracts all Anchor-specific
    /// structures for analysis.
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path identifier for the source file
    /// * `source_code` - Raw Rust source code content
    ///
    /// # Returns
    ///
    /// Returns `Ok(AnalysisContext)` on successful parsing, or an error
    /// if the source code cannot be parsed.
    ///
    /// # Errors
    ///
    /// Returns an error if the source code contains syntax errors that
    /// prevent parsing.
    pub fn from_source(file_path: &str, source_code: String) -> Result<Self> {
        let ast = syn::parse_file(&source_code)?;

        let accounts = extract_account_structs(&ast);
        let instructions = extract_instruction_handlers(&ast);
        let state_accounts = extract_state_accounts(&ast);
        let error_codes = extract_error_codes(&ast);
        
        // Extract program metadata
        let program_name = extract_program_name(&ast);
        let program_id = extract_program_id(&source_code);

        Ok(Self {
            file_path: file_path.to_string(),
            source_code,
            ast,
            accounts,
            instructions,
            state_accounts,
            error_codes,
            program_name,
            program_id,
            program_context: None,
        })
    }

    /// Retrieves a specific line from the source code.
    ///
    /// # Arguments
    ///
    /// * `line` - Line number (1-indexed)
    ///
    /// # Returns
    ///
    /// The content of the specified line, or `None` if out of bounds.
    pub fn get_source_line(&self, line: usize) -> Option<&str> {
        self.source_code.lines().nth(line.saturating_sub(1))
    }

    /// Retrieves a range of lines from the source code.
    ///
    /// # Arguments
    ///
    /// * `start_line` - Starting line number (1-indexed, inclusive)
    /// * `end_line` - Ending line number (1-indexed, inclusive)
    ///
    /// # Returns
    ///
    /// A string containing the specified lines joined with newlines.
    pub fn get_source_range(&self, start_line: usize, end_line: usize) -> String {
        self.source_code
            .lines()
            .skip(start_line.saturating_sub(1))
            .take(end_line - start_line + 1)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Represents an Anchor account struct marked with `#[derive(Accounts)]`.
///
/// Account structs define the accounts required by an instruction and
/// their validation constraints.
#[derive(Debug, Clone)]
pub struct AccountStruct {
    /// Name of the struct (e.g., "Initialize", "Transfer").
    pub name: String,

    /// Fields within the account struct.
    pub fields: Vec<AccountField>,

    /// Starting line number in the source file.
    pub start_line: usize,

    /// Ending line number in the source file.
    pub end_line: usize,
}

/// Represents a field within an Anchor account struct.
///
/// Each field corresponds to an account that must be passed to the instruction.
#[derive(Debug, Clone)]
pub struct AccountField {
    /// Field name identifier.
    pub name: String,

    /// Type of the account field.
    pub ty: AccountType,

    /// Constraints applied via `#[account(...)]` attribute.
    pub constraints: Vec<Constraint>,

    /// Whether the account is marked as mutable.
    pub is_mutable: bool,

    /// Whether the account requires a signature.
    pub is_signer: bool,

    /// Whether the account is being initialized.
    pub is_init: bool,

    /// Line number where the field is defined.
    pub line: usize,
}

/// Anchor account type classification.
///
/// Determines the level of automatic validation provided by the Anchor framework.
#[derive(Debug, Clone, PartialEq)]
pub enum AccountType {
    /// Typed account with automatic owner and discriminator validation.
    Account(String),

    /// Raw account info without automatic validation.
    AccountInfo,

    /// Account that must sign the transaction.
    Signer,

    /// Program account reference.
    Program(String),

    /// System program reference.
    SystemProgram,

    /// Explicitly unchecked account (requires manual validation).
    UncheckedAccount,

    /// System-owned account.
    SystemAccount,

    /// Legacy program account type.
    ProgramAccount(String),

    /// Unknown or unrecognized account type.
    Unknown(String),
}

/// Constraint applied to an account field.
///
/// Constraints define validation rules that Anchor enforces at runtime.
#[derive(Debug, Clone)]
pub struct Constraint {
    /// Parsed constraint type.
    pub constraint_type: ConstraintType,

    /// Raw constraint string as written in source.
    pub raw: String,

    /// Line number where the constraint is defined.
    pub line: usize,
}

/// Types of constraints that can be applied to account fields.
#[derive(Debug, Clone, PartialEq)]
pub enum ConstraintType {
    /// Initialize a new account.
    Init,

    /// Initialize if the account doesn't exist.
    InitIfNeeded,

    /// Mark account as mutable.
    Mut,

    /// Require account to be a signer.
    Signer,

    /// Validate relationship with another account field.
    HasOne(String),

    /// PDA seeds for address derivation.
    Seeds(Vec<String>),

    /// PDA bump seed.
    Bump,

    /// Account that pays for new account creation.
    Payer(String),

    /// Space allocation for new accounts.
    Space(String),

    /// Required program owner.
    Owner(String),

    /// Custom constraint expression.
    Constraint(String),

    /// Required account address.
    Address(String),

    /// Account to receive lamports on close.
    Close(String),

    /// Reallocation parameters.
    Realloc {
        size: String,
        payer: String,
        zero: bool,
    },

    /// Unrecognized constraint type.
    Unknown(String),
}

/// Represents an instruction handler function.
///
/// Instruction handlers are functions that take a `Context<T>` parameter
/// and implement the program's business logic.
#[derive(Debug, Clone)]
pub struct InstructionHandler {
    /// Function name.
    pub name: String,

    /// Associated accounts type (the `T` in `Context<T>`).
    pub accounts_type: String,

    /// Instruction arguments (excluding context).
    pub args: Vec<InstructionArg>,

    /// Starting line number.
    pub start_line: usize,

    /// Ending line number.
    pub end_line: usize,

    /// Arithmetic operations found in the function body.
    pub arithmetic_ops: Vec<ArithmeticOp>,

    /// Cross-program invocations found in the function body.
    pub cpi_calls: Vec<CpiCall>,
}

/// Argument passed to an instruction handler.
#[derive(Debug, Clone)]
pub struct InstructionArg {
    /// Argument name.
    pub name: String,

    /// Argument type as a string.
    pub ty: String,
}

/// Arithmetic operation found in instruction code.
#[derive(Debug, Clone)]
pub struct ArithmeticOp {
    /// Operation type (add, sub, mul, div).
    pub operation: String,

    /// Whether checked arithmetic is used.
    pub is_checked: bool,

    /// Line number of the operation.
    pub line: usize,

    /// Full expression as a string.
    pub expression: String,
}

/// Cross-program invocation (CPI) call.
#[derive(Debug, Clone)]
pub struct CpiCall {
    /// Target program identifier.
    pub program: String,

    /// Whether the program ID is hardcoded.
    pub is_program_hardcoded: bool,

    /// Line number of the CPI call.
    pub line: usize,
}

/// State account definition marked with `#[account]`.
#[derive(Debug, Clone)]
pub struct StateAccount {
    /// Account struct name.
    pub name: String,

    /// Fields as (name, type) pairs.
    pub fields: Vec<(String, String)>,

    /// Whether the account has a discriminator.
    pub has_discriminator: bool,

    /// Line number of the definition.
    pub line: usize,
}

/// Error code from `#[error_code]` enum.
#[derive(Debug, Clone)]
pub struct ErrorCode {
    /// Error variant name.
    pub name: String,

    /// Numeric error code if specified.
    pub code: Option<u32>,

    /// Error message if specified.
    pub message: Option<String>,
}

/// Parses Anchor files from a filesystem path.
///
/// Reads the file content and creates an analysis context.
///
/// # Arguments
///
/// * `path` - Path to the Rust source file
///
/// # Returns
///
/// Returns an `AnalysisContext` on success, or an error if the file
/// cannot be read or parsed.
pub fn parse_anchor_files(path: &Path) -> Result<AnalysisContext> {
    let source_code = std::fs::read_to_string(path)?;
    AnalysisContext::from_source(&path.to_string_lossy(), source_code)
}

/// Extracts the program name from the AST.
///
/// Looks for `#[program] pub mod program_name { ... }` pattern.
fn extract_program_name(ast: &syn::File) -> Option<String> {
    for item in &ast.items {
        if let syn::Item::Mod(item_mod) = item {
            // Check for #[program] attribute
            for attr in &item_mod.attrs {
                if attr.path().is_ident("program") {
                    return Some(item_mod.ident.to_string());
                }
            }
        }
    }
    None
}

/// Extracts the program ID from `declare_id!("...")` macro.
///
/// Uses regex to find the macro invocation in source code.
fn extract_program_id(source_code: &str) -> Option<String> {
    // Pattern: declare_id!("Base58ProgramId...")
    let re = regex::Regex::new(r#"declare_id!\s*\(\s*"([A-Za-z0-9]{32,44})"\s*\)"#).ok()?;
    re.captures(source_code)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}
