//! # POC Generator Module
//!
//! @title Proof-of-Concept Exploit Generator
//! @author Ramprasad
//!
//! Generates TypeScript proof-of-concept exploit tests for detected
//! vulnerabilities using the Handlebars templating engine.
//!
//! ## Generated Files
//!
//! - Individual POC files per detector (e.g., `poc_v001.ts`)
//! - Combined POC file with all exploits (`poc_all_exploits.ts`)

mod templates;

use crate::report::Finding;
use anyhow::Result;
use handlebars::Handlebars;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Generator for TypeScript proof-of-concept exploit tests.
///
/// Uses Handlebars templates to create structured test files that
/// demonstrate how vulnerabilities can be exploited.
pub struct PocGenerator {
    handlebars: Handlebars<'static>,
}

impl PocGenerator {
    /// Creates a new POC generator with registered templates.
    pub fn new() -> Self {
        let mut handlebars = Handlebars::new();
        handlebars.set_strict_mode(false);

        Self { handlebars }
    }

    /// Generates all POC files for the given findings.
    ///
    /// Creates individual files for each detector type plus a combined
    /// file containing all exploits.
    ///
    /// # Arguments
    ///
    /// * `findings` - Vector of security findings
    /// * `output_dir` - Directory to write POC files to
    /// * `scan_path` - Original scan path to detect Anchor.toml
    ///
    /// # Returns
    ///
    /// A vector of paths to generated files.
    pub fn generate_all(&self, findings: &[Finding], output_dir: &Path, scan_path: Option<&Path>) -> Result<Vec<PathBuf>> {
        let mut generated_files = Vec::new();

        // Auto-detect program name from Anchor.toml
        let program_name = scan_path
            .and_then(|p| self.detect_program_name(p))
            .unwrap_or_else(|| "your_program".to_string());

        // Generate single comprehensive POC file with all exploits
        let poc_path = output_dir.join("exploit_poc.ts");
        let poc_content = self.generate_comprehensive_poc(findings, &program_name)?;
        std::fs::write(&poc_path, poc_content)?;
        generated_files.push(poc_path);

        // Generate attack path visualization with Mermaid diagrams
        let attack_path = output_dir.join("attack_paths.md");
        let attack_content = self.generate_attack_diagrams(findings, &program_name);
        std::fs::write(&attack_path, attack_content)?;
        generated_files.push(attack_path);

        Ok(generated_files)
    }

    /// Generates a single comprehensive POC file with all exploits.
    ///
    /// Creates a ready-to-run TypeScript file containing test cases for
    /// every detected vulnerability, organized by severity.
    fn generate_comprehensive_poc(&self, findings: &[Finding], program_name: &str) -> Result<String> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Count by severity
        let critical_count = findings.iter().filter(|f| f.severity == crate::report::Severity::Critical).count();
        let high_count = findings.iter().filter(|f| f.severity == crate::report::Severity::High).count();

        // Convert snake_case to PascalCase for TypeScript import
        let pascal_name = self.to_pascal_case(program_name);

        let mut content = format!(r#"/**
 * ============================================================
 *                    ANCHOR-SENTINEL POC
 * ============================================================
 * 
 * Program: {program_name}
 * Generated: {timestamp}
 * 
 * FINDINGS SUMMARY:
 *   - Critical: {critical_count}
 *   - High: {high_count}
 *   - Total: {total}
 * 
 * HOW TO USE:
 * 1. Ensure your program is built: anchor build
 * 2. Run: anchor test --skip-local-validator exploit_poc.ts
 * 
 * ============================================================
 */

import * as anchor from "@coral-xyz/anchor";
import {{ Program }} from "@coral-xyz/anchor";
import {{ 
    PublicKey, 
    Keypair, 
    SystemProgram,
    LAMPORTS_PER_SOL,
    SYSVAR_RENT_PUBKEY
}} from "@solana/web3.js";
import {{ expect }} from "chai";
import {{ TOKEN_PROGRAM_ID }} from "@solana/spl-token";

// ============================================================
// AUTO-DETECTED PROGRAM IMPORT
// ============================================================
import {{ {pascal_name} }} from "../target/types/{program_name}";

describe("Anchor-Sentinel Exploit POC", () => {{
    // Setup
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);
    
    // Program reference - auto-detected from Anchor workspace
    const program = anchor.workspace.{pascal_name} as Program<{pascal_name}>;
    
    // Attacker and victim keypairs
    const attacker = Keypair.generate();
    const victim = Keypair.generate();

    before(async () => {{
        // Fund attacker account
        const sig = await provider.connection.requestAirdrop(
            attacker.publicKey,
            10 * LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(sig);
        console.log("Attacker funded:", attacker.publicKey.toString());
        
        // Fund victim account
        const sig2 = await provider.connection.requestAirdrop(
            victim.publicKey,
            10 * LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(sig2);
        console.log("Victim funded:", victim.publicKey.toString());
    }});

"#, program_name = program_name, timestamp = timestamp, critical_count = critical_count, 
    high_count = high_count, total = findings.len(), pascal_name = pascal_name);


        // Group findings by detector for organized output
        let mut grouped: std::collections::HashMap<String, Vec<&Finding>> = std::collections::HashMap::new();
        for finding in findings {
            grouped
                .entry(finding.detector_id.clone())
                .or_default()
                .push(finding);
        }

        // Sort detector IDs to get consistent output order
        let mut detector_ids: Vec<_> = grouped.keys().collect();
        detector_ids.sort();

        for detector_id in detector_ids {
            let detector_findings = grouped.get(detector_id).unwrap();
            
            // Section header for each detector type
            content.push_str(&format!(r#"
    // ============================================================
    // {} EXPLOITS ({} found)
    // ============================================================
"#, 
                self.get_detector_name(detector_id),
                detector_findings.len()
            ));

            // Generate test case for each finding
            for (idx, finding) in detector_findings.iter().enumerate() {
                content.push_str(&self.generate_exploit_test(finding, idx + 1));
            }
        }

        // Close the describe block
        content.push_str(r#"
});

// ============================================================
// HELPER FUNCTIONS
// ============================================================

async function logExploitResult(name: string, success: boolean) {
    if (success) {
        console.log(`[VULNERABLE] ${name}`);
    } else {
        console.log(`[SECURE] ${name}`);
    }
}
"#);

        Ok(content)
    }

    /// Gets human-readable name for detector.
    fn get_detector_name(&self, detector_id: &str) -> &'static str {
        match detector_id {
            "V001" => "MISSING SIGNER",
            "V002" => "MISSING OWNER",
            "V003" => "INTEGER OVERFLOW / PRECISION LOSS",
            "V004" => "PDA COLLISION",
            "V005" => "REINITIALIZATION",
            "V006" => "UNSAFE CPI",
            _ => "VULNERABILITY",
        }
    }

    /// Detects program name from Anchor.toml in the project.
    ///
    /// Searches for Anchor.toml starting from the scan path and parses
    /// the program name from [programs.localnet] or [programs.devnet].
    fn detect_program_name(&self, scan_path: &Path) -> Option<String> {
        // Try to find Anchor.toml by walking up from scan path
        let mut current = scan_path.to_path_buf();
        
        loop {
            let anchor_toml = current.join("Anchor.toml");
            if anchor_toml.exists() {
                if let Ok(content) = std::fs::read_to_string(&anchor_toml) {
                    // Parse [programs.localnet] or similar
                    // Format: program_name = "ProgramId"
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if !trimmed.starts_with('#') && !trimmed.starts_with('[') {
                            if let Some((name, _)) = trimmed.split_once('=') {
                                let name = name.trim();
                                if !name.is_empty() && !name.contains('.') {
                                    return Some(name.to_string());
                                }
                            }
                        }
                    }
                }
                return None;
            }
            
            if !current.pop() {
                break;
            }
        }
        
        None
    }

    /// Converts snake_case to PascalCase for TypeScript imports.
    ///
    /// # Example
    ///
    /// "meta_lend" -> "MetaLend"
    /// "my_program" -> "MyProgram"
    fn to_pascal_case(&self, s: &str) -> String {
        s.split('_')
            .map(|part| {
                let mut chars = part.chars();
                match chars.next() {
                    None => String::new(),
                    Some(first) => first.to_uppercase().chain(chars).collect(),
                }
            })
            .collect()
    }

    /// Generates attack path visualization with Mermaid diagrams.
    ///
    /// Creates a Markdown file with Mermaid flowcharts showing the
    /// attack path for each vulnerability type.
    fn generate_attack_diagrams(&self, findings: &[Finding], program_name: &str) -> String {
        let mut content = format!(r#"# Attack Path Visualization

**Program**: {}
**Generated by**: Anchor-Sentinel

This document contains Mermaid flowcharts showing exploit paths for each detected vulnerability.

---

"#, program_name);

        // Group findings by detector
        let mut grouped: std::collections::HashMap<String, Vec<&Finding>> = std::collections::HashMap::new();
        for finding in findings {
            grouped.entry(finding.detector_id.clone()).or_default().push(finding);
        }

        // Generate diagrams for each vulnerability type
        for (detector_id, detector_findings) in &grouped {
            content.push_str(&format!(
                "## {} - {} ({})\n\n",
                detector_id,
                self.get_detector_name(detector_id),
                detector_findings.len()
            ));

            // Add the attack flow diagram
            content.push_str(&self.get_attack_diagram(detector_id));

            // List all findings for this detector
            content.push_str("\n### Locations Found\n\n");
            for (idx, finding) in detector_findings.iter().enumerate() {
                content.push_str(&format!(
                    "{}. **{}** - `{}`\n",
                    idx + 1,
                    finding.location,
                    finding.file_path
                ));
            }
            content.push_str("\n---\n\n");
        }

        content
    }

    /// Returns Mermaid diagram for specific vulnerability type.
    fn get_attack_diagram(&self, detector_id: &str) -> String {
        match detector_id {
            "V001" => r#"```mermaid
flowchart TD
    A[Attacker] -->|1. Identifies| B[Missing Signer Check]
    B -->|2. Crafts TX| C[Transaction Without Signature]
    C -->|3. Passes| D[Account as Non-Signer]
    D -->|4. Executes| E[Unauthorized Action]
    E -->|5. Result| F[💰 Privilege Escalation]
    
    style A fill:#ff6b6b,color:white
    style F fill:#ff6b6b,color:white
    style B fill:#ffd93d,color:black
```

**Attack Flow**:
1. Attacker identifies account without signer constraint
2. Crafts transaction passing victim's public key WITHOUT signature requirement
3. Program accepts because no `Signer<'info>` or `#[account(signer)]` check
4. Executes privileged action on behalf of victim

"#.to_string(),

            "V002" => r#"```mermaid
flowchart TD
    A[Attacker] -->|1. Creates| B[Fake Account]
    B -->|2. Sets| C[Arbitrary Data]
    C -->|3. Passes to| D[Vulnerable Instruction]
    D -->|4. No Owner Check| E[Program Accepts]
    E -->|5. Result| F[💰 Data Injection]
    
    style A fill:#ff6b6b,color:white
    style F fill:#ff6b6b,color:white
    style D fill:#ffd93d,color:black
```

**Attack Flow**:
1. Attacker creates account with System Program (not target program owner)
2. Fills account with malicious data (fake balances, permissions)
3. Passes fake account to instruction expecting program-owned account
4. Program reads attacker-controlled data as legitimate

"#.to_string(),

            "V003" => r#"```mermaid
flowchart TD
    A[Attacker] -->|1. Identifies| B[Unchecked Arithmetic]
    B -->|2. Crafts| C[Overflow Value]
    C -->|3. Submits| D[MAX_U64 + 1]
    D -->|4. Wraps to| E[Zero or Small Value]
    E -->|5. Result| F[💰 Balance Manipulation]
    
    style A fill:#ff6b6b,color:white
    style F fill:#ff6b6b,color:white
    style B fill:#ffd93d,color:black
```

**Attack Flow**:
1. Finds unchecked `+`, `-`, `*` operations on token amounts
2. Calculates overflow value: `MAX_U64 - current_balance + 1`
3. After addition, balance wraps to 0 or small number
4. Alternative: Precision loss via `a / b * c` instead of `a * c / b`

"#.to_string(),

            "V004" => r#"```mermaid
flowchart TD
    A[Attacker] -->|1. Analyzes| B[PDA Seeds]
    B -->|2. Finds| C[Static/Weak Seeds]
    C -->|3. Derives| D[Same PDA]
    D -->|4. Collides with| E[Legitimate Account]
    E -->|5. Result| F[💰 Account Hijacking]
    
    style A fill:#ff6b6b,color:white
    style F fill:#ff6b6b,color:white
    style C fill:#ffd93d,color:black
```

**Attack Flow**:
1. Analyzes PDA derivation seeds in program
2. Finds seeds like `["config"]` without user-specific data
3. Derives same PDA address as legitimate user
4. Overwrites or confuses account data

"#.to_string(),

            "V005" => r#"```mermaid
flowchart TD
    A[Victim] -->|1. Initializes| B[Account with Data]
    B -->|2. Later...| C[Attacker Calls Same Instruction]
    C -->|3. init_if_needed| D[Reinitializes Account]
    D -->|4. Overwrites| E[Victim Authority]
    E -->|5. Result| F[💰 Account Takeover]
    
    style A fill:#4ecdc4,color:white
    style C fill:#ff6b6b,color:white
    style F fill:#ff6b6b,color:white
    style D fill:#ffd93d,color:black
```

**Attack Flow**:
1. Victim initializes their account with legitimate data
2. Attacker calls same instruction targeting victim's account
3. `init_if_needed` allows reinitialization
4. Attacker becomes new authority of victim's account

"#.to_string(),

            "V006" => r#"```mermaid
flowchart TD
    A[Attacker] -->|1. Deploys| B[Malicious Program]
    B -->|2. Same Interface| C[Mimics Expected Program]
    C -->|3. Passes to| D[Vulnerable CPI Call]
    D -->|4. invoke without| E[Program ID Validation]
    E -->|5. Executes| F[Attacker Code]
    F -->|6. Result| G[💰 Phantom Invocation]
    
    style A fill:#ff6b6b,color:white
    style G fill:#ff6b6b,color:white
    style D fill:#ffd93d,color:black
```

**Attack Flow**:
1. Attacker deploys malicious program with same function interface
2. Passes malicious program ID to vulnerable instruction
3. Raw `invoke()` or `invoke_signed()` without program ID check
4. Victim program executes attacker's code with its privileges

"#.to_string(),

            _ => r#"```mermaid
flowchart TD
    A[Attacker] -->|1. Identifies| B[Vulnerability]
    B -->|2. Exploits| C[Weakness]
    C -->|3. Result| D[💰 Profit]
    
    style A fill:#ff6b6b,color:white
    style D fill:#ff6b6b,color:white
```
"#.to_string(),
        }
    }

    /// Generates a single exploit test case with all details filled in.
    fn generate_exploit_test(&self, finding: &Finding, index: usize) -> String {
        let (instruction_name, vulnerable_account) = self.parse_location(&finding.location);
        let severity_badge = match finding.severity {
            crate::report::Severity::Critical => "[CRITICAL]",
            crate::report::Severity::High => "[HIGH]",
            crate::report::Severity::Medium => "[MEDIUM]",
            crate::report::Severity::Low => "[LOW]",
            crate::report::Severity::Info => "[INFO]",
        };

        let escaped_title = finding.title.replace('`', "'").replace('"', "'");
        
        format!(r#"
    it("{severity} #{index}: {title}", async () => {{
        /**
         * FILE: {file_path}
         * LINE: {line}
         * LOCATION: {location}
         * 
         * VULNERABILITY: {description}
         * 
         * REMEDIATION: {remediation}
         */

        console.log("\n{severity} Testing: {title}");
        console.log("Location: {file_path}:{line}");

        try {{
            {exploit_code}

            logExploitResult("{location}", true);
        }} catch (error: any) {{
            console.log("Error:", error.message);
            logExploitResult("{location}", false);
        }}
    }});
"#,
            severity = severity_badge,
            index = index,
            title = escaped_title,
            file_path = finding.file_path,
            line = finding.line,
            location = finding.location,
            description = finding.description.lines().next().unwrap_or("").replace('"', "'"),
            remediation = finding.remediation.lines().next().unwrap_or("").replace('"', "'"),
            exploit_code = self.generate_exploit_code(&finding.detector_id, &instruction_name, &vulnerable_account)
        )
    }

    /// Generates specific exploit code based on vulnerability type.
    fn generate_exploit_code(&self, detector_id: &str, instruction_name: &str, vulnerable_account: &str) -> String {
        match detector_id {
            "V001" => format!(r#"// EXPLOIT: Call instruction without proper signer
            // The '{account}' account is not verified as a signer
            // Attacker can pass any public key without signing
            
            const fakeAuthority = victim.publicKey;
            
            await program.methods
                .{instruction}()
                .accounts({{
                    {account}: fakeAuthority,  // NOT signing - should fail if protected
                    systemProgram: SystemProgram.programId,
                }})
                .signers([attacker])
                .rpc();
            
            console.log("VULNERABLE: Instruction executed without proper signer!");
            console.log("Fake authority:", fakeAuthority.toString());"#, 
                instruction = instruction_name, 
                account = vulnerable_account
            ),
            
            "V002" => format!(r#"// EXPLOIT: Pass account owned by different program
            // The '{account}' lacks owner validation
            // Attacker can pass malicious account with fake data
            
            const fakeAccount = Keypair.generate();
            
            // Create and try to pass a fake account that is NOT owned by the program
            await program.methods
                .{instruction}()
                .accounts({{
                    {account}: fakeAccount.publicKey,  // Wrong owner!
                    systemProgram: SystemProgram.programId,
                }})
                .signers([attacker, fakeAccount])
                .rpc();
            
            console.log("VULNERABLE: Accepted account with wrong owner!");
            console.log("Fake account:", fakeAccount.publicKey.toString());"#,
                instruction = instruction_name,
                account = vulnerable_account
            ),
            
            "V003" => format!(r#"// EXPLOIT: Trigger integer overflow or precision loss
            // Unchecked arithmetic at '{location}'
            
            const MAX_U64 = BigInt("18446744073709551615");
            
            // Test with extreme values to trigger overflow
            const overflowAmount = new anchor.BN(MAX_U64.toString());
            
            await program.methods
                .{instruction}(overflowAmount)
                .accounts({{
                    user: attacker.publicKey,
                    systemProgram: SystemProgram.programId,
                }})
                .signers([attacker])
                .rpc();
            
            console.log("VULNERABLE: Arithmetic operation did not revert on overflow!");"#,
                instruction = instruction_name,
                location = vulnerable_account
            ),
            
            "V004" => format!(r#"// EXPLOIT: PDA seed collision or bump manipulation
            // Weak seeds at '{location}'
            
            const [pdaAddress, bump] = PublicKey.findProgramAddressSync(
                [Buffer.from("{instruction}")],  // Weak static seed - easily predictable
                program.programId
            );
            
            // Try to derive colliding PDA or use non-canonical bump
            await program.methods
                .{instruction}()
                .accounts({{
                    {account}: pdaAddress,
                    user: attacker.publicKey,
                    systemProgram: SystemProgram.programId,
                }})
                .signers([attacker])
                .rpc();
            
            console.log("PDA Address:", pdaAddress.toString());
            console.log("Bump:", bump);"#,
                instruction = instruction_name,
                account = vulnerable_account,
                location = vulnerable_account
            ),
            
            "V005" => format!(r#"// EXPLOIT: Reinitialize already-initialized account
            // The '{account}' uses init_if_needed
            
            // Step 1: Create victim account reference
            const victimAccount = victim.publicKey;
            
            // Step 2: Attacker calls instruction to reinitialize existing account
            await program.methods
                .{instruction}()
                .accounts({{
                    {account}: victimAccount,  // Already initialized!
                    payer: attacker.publicKey,
                    systemProgram: SystemProgram.programId,
                }})
                .signers([attacker])
                .rpc();
            
            console.log("VULNERABLE: Account was reinitialized!");"#,
                instruction = instruction_name,
                account = vulnerable_account
            ),
            
            "V006" => format!(r#"// EXPLOIT: Phantom CPI invocation
            // Raw invoke at '{location}' - no program ID validation
            
            // In a real attack, deploy a malicious program first
            const maliciousProgramId = Keypair.generate().publicKey;
            
            // Pass malicious program to vulnerable CPI call
            await program.methods
                .{instruction}()
                .accounts({{
                    targetProgram: maliciousProgramId,  // Attacker's program!
                    user: attacker.publicKey,
                    systemProgram: SystemProgram.programId,
                }})
                .signers([attacker])
                .rpc();
            
            console.log("VULNERABLE: CPI executed with attacker's program!");
            console.log("Malicious program:", maliciousProgramId.toString());"#,
                instruction = instruction_name,
                location = vulnerable_account
            ),
            
            _ => format!(r#"// Vulnerability type: {{detector_id}}
            // Location: '{location}'
            
            console.log("Test case for {{detector_id}} vulnerability");"#,
                location = vulnerable_account
            ),
        }
    }

    /// Parses location to extract instruction and account names.
    fn parse_location(&self, location: &str) -> (String, String) {
        if location.contains("::") {
            let parts: Vec<&str> = location.split("::").collect();
            if parts.len() >= 2 {
                return (parts[0].to_string(), parts[1].to_string());
            }
        }
        if location.starts_with("Line ") {
            return ("vulnerable_function".to_string(), location.to_string());
        }
        ("unknown".to_string(), location.to_string())
    }

    /// Returns the appropriate template for a detector.
    fn get_template_for_detector(&self, detector_id: &str) -> &'static str {
        let header = templates::HEADER_TEMPLATE;
        let body = match detector_id {
            "V001" => templates::MISSING_SIGNER_TEMPLATE,
            "V002" => templates::MISSING_OWNER_TEMPLATE,
            "V003" => templates::INTEGER_OVERFLOW_TEMPLATE,
            "V004" => templates::PDA_COLLISION_TEMPLATE,
            "V005" => templates::UNCHECKED_INIT_TEMPLATE,
            "V006" => templates::UNSAFE_CPI_TEMPLATE,
            _ => templates::GENERIC_TEMPLATE,
        };

        // Combine header with body
        Box::leak(format!("{}\n{}", header, body).into_boxed_str())
    }

    /// Generates the common header for POC files.
    fn generate_header(&self, detector_id: &str, description: &str) -> String {
        format!(
            r#"/**
 * Anchor-Sentinel POC Exploit: {}
 * ===========================================
 * Description: {}
 * Generated: {}
 *
 */

import * as anchor from "@coral-xyz/anchor";
import {{ Program }} from "@coral-xyz/anchor";
import {{
    PublicKey,
    Keypair,
    SystemProgram,
    Transaction,
    LAMPORTS_PER_SOL
}} from "@solana/web3.js";
import {{ expect }} from "chai";

"#,
            detector_id,
            description,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        )
    }

    /// Generates a test case for a single finding.
    fn generate_test_case(&self, finding: &Finding) -> String {
        let escaped_title = finding.title.replace('`', "\\`").replace('"', "\\\"");
        let escaped_desc = finding.description.replace('`', "\\`").replace('"', "\\\"");

        format!(
            r#"
describe("[{}] {}", () => {{
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const attacker = Keypair.generate();

    before(async () => {{
        // Fund attacker account
        const sig = await provider.connection.requestAirdrop(
            attacker.publicKey,
            5 * LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(sig);
    }});

    it("should demonstrate vulnerability: {}", async () => {{
        console.log("\nTarget: {}");
        console.log("Location: {}:{}", );

        /**
         * EXPLOIT STRATEGY:
         * -----------------
         * {}
         */

        try {{
            // TODO: Implement program-specific exploit
            // 1. Setup accounts
            // 2. Craft malicious instruction
            // 3. Execute exploit
            // 4. Verify exploitation succeeded

            console.log("VULNERABLE: Exploit could succeed!");
        }} catch (error: any) {{
            console.log("Result:", error.message);
        }}
    }});
}});
"#,
            finding.detector_id,
            escaped_title,
            finding.location,
            finding.title,
            finding.file_path,
            finding.line,
            escaped_desc.lines().take(3).collect::<Vec<_>>().join("\n         * ")
        )
    }
}

impl Default for PocGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Data structure for template rendering.
#[derive(Debug, Serialize)]
struct PocTemplateData<'a> {
    detector_id: &'a str,
    program_name: String,
    timestamp: u64,
    findings: Vec<FindingData<'a>>,
}

impl<'a> PocTemplateData<'a> {
    fn new(detector_id: &'a str, findings: &[&'a Finding]) -> Self {
        let program_name = findings
            .first()
            .map(|f| {
                std::path::Path::new(&f.file_path)
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            })
            .unwrap_or_else(|| "unknown".to_string());

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            detector_id,
            program_name,
            timestamp,
            findings: findings.iter().map(|f| FindingData::from(*f)).collect(),
        }
    }
}

/// Serializable finding data for templates.
///
/// Contains extracted fields for easy template injection:
/// - `instruction_name`: The instruction or context struct name (e.g., "withdraw_funds")
/// - `vulnerable_account`: The vulnerable account field name (e.g., "admin_key")
#[derive(Debug, Serialize)]
struct FindingData<'a> {
    title: &'a str,
    description: &'a str,
    location: &'a str,
    file_path: &'a str,
    line: usize,
    code_snippet: Option<&'a str>,
    /// The instruction/context name extracted from location (e.g., "MissingSigner")
    instruction_name: String,
    /// The vulnerable account name extracted from location (e.g., "admin_config")
    vulnerable_account: String,
}

impl<'a> From<&'a Finding> for FindingData<'a> {
    fn from(finding: &'a Finding) -> Self {
        // Extract instruction_name and vulnerable_account from location
        // Location format: "ContextName::account_name" or "function_name::operation"
        let (instruction_name, vulnerable_account) = Self::parse_location(&finding.location);
        
        Self {
            title: &finding.title,
            description: &finding.description,
            location: &finding.location,
            file_path: &finding.file_path,
            line: finding.line,
            code_snippet: finding.code_snippet.as_deref(),
            instruction_name,
            vulnerable_account,
        }
    }
}

impl<'a> FindingData<'a> {
    /// Parses the location string to extract instruction name and vulnerable account.
    ///
    /// # Examples
    ///
    /// - "MissingSigner::admin_config" → ("MissingSigner", "admin_config")
    /// - "withdraw_funds::sub" → ("withdraw_funds", "sub")
    /// - "Line 42" → ("unknown", "unknown")
    fn parse_location(location: &str) -> (String, String) {
        if location.contains("::") {
            let parts: Vec<&str> = location.split("::").collect();
            if parts.len() >= 2 {
                return (parts[0].to_string(), parts[1].to_string());
            }
        }
        // Fallback: try to extract from the location string
        ("unknown".to_string(), "unknown".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Severity;
    use tempfile::TempDir;

    #[test]
    fn test_poc_generation() {
        let temp_dir = TempDir::new().unwrap();
        let generator = PocGenerator::new();

        let findings = vec![Finding {
            id: "test-1".to_string(),
            detector_id: "V001".to_string(),
            title: "Missing signer".to_string(),
            description: "Authority lacks signer".to_string(),
            severity: Severity::Critical,
            file_path: "program.rs".to_string(),
            line: 10,
            location: "Withdraw::authority".to_string(),
            code_snippet: None,
            remediation: "Add Signer type".to_string(),
            cwe: None,
            confidence: 0.9,
        }];

        let files = generator.generate_all(&findings, temp_dir.path(), None).unwrap();

        assert!(!files.is_empty());
        assert!(files.iter().any(|f| f.file_name().unwrap() == "poc_v001.ts"));
    }
}
