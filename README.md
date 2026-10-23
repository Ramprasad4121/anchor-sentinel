<p align="center">
  <img src="assets/anchor-sentinel-logo.png" alt="Anchor-Sentinel Logo" width="600"/>
</p>

<h1 align="center">Anchor-Sentinel</h1>

<p align="center">
  <strong>Static security analyzer for Solana Anchor programs.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust"/>
  <img src="https://img.shields.io/badge/Solana-9945FF?style=for-the-badge&logo=solana&logoColor=white" alt="Solana"/>
  <img src="https://img.shields.io/badge/Anchor-0052FF?style=for-the-badge&logo=anchor&logoColor=white" alt="Anchor"/>
  <img src="https://img.shields.io/badge/License-GPL--3.0-blue?style=for-the-badge" alt="License"/>
</p>

Anchor-Sentinel scans Anchor programs written in Rust for common Solana security bugs: missing signer checks, unchecked owners, unsafe CPIs, weak PDA seeds and more. It runs 30 detectors on the parsed Rust AST, prints each finding with file, line, severity and a fix, and can write TypeScript exploit test scaffolds for what it finds.

It is a first pass before an audit, not a replacement for one.

## Quick start

```bash
# Linux x86_64 prebuilt binary (v0.3.1). macOS arm64 build is on the release page too.
curl -LO https://github.com/Ramprasad4121/anchor-sentinel/releases/download/v0.3.1/anchor-sentinel-v0.3.1-x86_64-unknown-linux-musl.tar.gz
tar xzf anchor-sentinel-v0.3.1-x86_64-unknown-linux-musl.tar.gz
sudo mv anchor-sentinel /usr/local/bin/

# scan your Anchor program
anchor-sentinel scan ./programs
```

Real output on the bundled test program:

```
$ anchor-sentinel scan tests/test_contracts/vulnerable_vault.rs

#1 CRITICAL [V001] Account `destination` in `CloseAccount` may require signer authorization
   Location: tests/test_contracts/vulnerable_vault.rs:151
   The account `destination` appears to be an authority or privileged account (based on naming: 'destination') but does not have a signer constraint. This could allow unauthorized users to perform privileged operations.

   Code:
   #[account(mut)]
   pub destination: AccountInfo<'info>,
   Reference: CWE-862

   Remediation:
   Add a signer constraint to the account:
   - Use `Signer<'info>` type for explicit signers
   - Add `#[account(signer)]` constraint

#1 CRITICAL [V001] Account `destination` in `CloseAccount` may require signer authorization
#2 CRITICAL [V006] Unsafe CPI in `emergency_withdraw`
#3 CRITICAL [V021] PDA 'state' without seeds verification
#4 CRITICAL [V021] PDA 'state' without seeds verification
#5 CRITICAL [V021] PDA 'vault' without seeds verification
#6 CRITICAL [V021] PDA 'state' without seeds verification
#7 CRITICAL [V021] PDA 'state' without seeds verification
#8 CRITICAL [V009] CPI without reentrancy guard
#9 CRITICAL [V025] Arbitrary CPI with unverified program 'token_program'
#10 HIGH [V002] Account `vault` in `UnsafeDeposit` lacks owner validation
#11 HIGH [V002] Account `destination` in `CloseAccount` lacks owner validation
#12 HIGH [V003] Unchecked `mul` operation in `collect_fees`
#13 HIGH [V004] Weak PDA seeds for `profile` in `BadPda`
#14 MEDIUM [V026] Division before multiplication may cause precision loss

[*] Summary: 9 Critical | 4 High | 1 Medium | 0 Low | 0 Info
[!] Total: 14 issue(s) found
```

## Install

**Prebuilt binary.** Download from the [v0.3.1 release](https://github.com/Ramprasad4121/anchor-sentinel/releases/tag/v0.3.1): Linux x86_64 (static, musl) and macOS Apple Silicon (`aarch64-apple-darwin`). Each archive has a `.sha256` file next to it. Built and smoke tested by the release workflow.

**Cargo (any OS with Rust):**
```bash
cargo install --git https://github.com/Ramprasad4121/anchor-sentinel --tag v0.3.1
```

**From source:**
```bash
git clone https://github.com/Ramprasad4121/anchor-sentinel
cd anchor-sentinel
cargo install --path .
```

## Usage

```bash
anchor-sentinel scan .                              # scan a project
anchor-sentinel scan ./programs                     # subdirectories are included
anchor-sentinel scan ./programs --severity high     # only High and Critical
anchor-sentinel scan ./programs --only V001,V002    # run specific detectors
anchor-sentinel scan ./programs --exclude V009,V010 # skip noisy detectors
anchor-sentinel scan ./programs --format json       # json | sarif | markdown | github | terminal (default)
anchor-sentinel scan ./programs --format markdown --output ./reports   # writes security_report.md
anchor-sentinel scan ./programs --generate-poc --output ./pocs         # exploit test scaffolds
anchor-sentinel diff ./v1 ./v2                      # new and fixed issues between two versions
anchor-sentinel init                                # writes .github/workflows/sentinel.yml
anchor-sentinel list                                # every detector with severity
```

With `--format json`, `--format sarif` or `--format github` only the report goes to stdout (banner and status go to stderr), so you can pipe it into `jq` or a CI step. `github` prints GitHub Actions annotations so findings show inline on PRs.

### GitHub code scanning (SARIF)

`--format sarif` writes SARIF 2.1.0 with one rule per detector, the fix text on every result, repo relative paths, and a fingerprint that ignores line numbers so alerts keep their identity when code moves. Upload it like this:

```yaml
- run: anchor-sentinel scan . --format sarif --output results
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results/anchor-sentinel.sarif
```

### Exploit PoC scaffolds

`--generate-poc` writes two files into the output folder:

- `exploit_poc.ts`: one Mocha/Anchor test per finding, with attacker and victim keypairs, the file and line, and the attack attempt.
- `attack_paths.md`: Mermaid diagrams of each attack path.

The tests are scaffolds. Instruction and account names are guessed from the source, so expect to adjust them. To run one, copy it into your Anchor workspace `tests/` folder and run `anchor test` (needs the Anchor CLI, a local validator, and `@coral-xyz/anchor`, `@solana/web3.js`, `@solana/spl-token`, `chai`).

## How it works

1. Parses every `.rs` file into a Rust AST with `syn` (not regex on raw text).
2. Builds a program context: `#[derive(Accounts)]` structs, constraints, instruction handlers, CPIs.
3. Runs taint tracking (user input to sensitive sinks) and a control flow graph per handler.
4. Each detector reads that context and reports findings with CWE references and a fix.

## Detectors

Output of `anchor-sentinel list` (30 detectors; ID V020 is not used):

| ID | Name | Severity |
|----|------|----------|
| V001 | Missing Signer Check | Critical |
| V002 | Missing Owner Check | High |
| V003 | Integer Overflow/Underflow | High |
| V004 | PDA Seed Collision/Weakness | High |
| V005 | Unchecked Account Initialization | High |
| V006 | Unsafe CPI | Critical |
| V007 | Token-2022 Security Risk | High |
| V008 | Missing PDA Bump Check | Critical |
| V009 | Reentrancy via CPI | Critical |
| V010 | Unchecked Amount in Transfers | High |
| V011 | Weak Authority Delegation | High |
| V012 | Rent Exemption Bypass | Medium |
| V013 | Missing Close Account | Medium |
| V014 | Oracle Dependency Risks | High |
| V015 | Sequence Number Mismatch | Critical |
| V016 | Token Mint/Burn Without Supply Check | High |
| V017 | Cross-Program Upgradeability Gaps | Medium |
| V018 | Error Handling Suppression | Low |
| V019 | Loop Iteration Overflows | High |
| V021 | Unverified Seeds in Derived Accounts | Critical |
| V022 | Lamports Rounding Errors | Medium |
| V023 | Tainted Data Flow | High |
| V024 | Account Used Without Validation | High |
| V025 | Arbitrary CPI Program ID | Critical |
| V026 | Precision Loss | Medium |
| V027 | Scope-Limited Validation | High |
| V028 | Duplicate Mutable Accounts | Medium |
| V029 | Unchecked Sysvar Address | Medium |
| V030 | Type Cosplay | High |
| V031 | Manual Close Without Cleanup | Medium |
| V032 | Precompile Offsets Not Checked | High |

## Benchmark

Tested against [coral-xyz/sealevel-attacks](https://github.com/coral-xyz/sealevel-attacks) (11 bug classes, insecure vs fixed versions). Short version: 4 classes detected, 1 partial, 6 missed; the target finding no longer fires on any hand-fixed version. Full table, misses and noisy detectors in [BENCHMARK.md](./BENCHMARK.md).

## Limitations

- Static analysis only. It can miss bugs and it does report false positives; V009, V010, V021 and V024 are the noisiest today.
- No detectors yet for type cosplay, reinitialization, duplicate mutable accounts, PDA sharing, account closing or sysvar address checks (see BENCHMARK.md).
- Anchor programs only. Native and Pinocchio programs are not supported yet.
- Not a replacement for a manual audit.

## Changelog

See [CHANGELOG.md](./CHANGELOG.md).

## License

GPL-3.0. See [LICENSE](./LICENSE).
