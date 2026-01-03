<p align="center">
  <img src="assets/anchor-sentinel-logo.png" alt="Anchor-Sentinel Logo" width="600"/>
</p>

<h1 align="center">Anchor-Sentinel</h1>

<p align="center">
  <strong>Static security analyzer for Solana Anchor smart contracts.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust"/>
  <img src="https://img.shields.io/badge/Solana-9945FF?style=for-the-badge&logo=solana&logoColor=white" alt="Solana"/>
  <img src="https://img.shields.io/badge/Anchor-0052FF?style=for-the-badge&logo=anchor&logoColor=white" alt="Anchor"/>
  <img src="https://img.shields.io/badge/License-GPL--3.0-blue?style=for-the-badge" alt="License"/>
</p>

<p align="center">
 Anchor-Sentinel is a static analysis framework for Solana & Anchor programs written in Rust. It runs a suite of vulnerability detectors to identify critical security flaws, prints detailed audit reports, and—unlike traditional tools—automatically generates executable Proof-of-Concept (POC) exploits. Anchor-Sentinel enables developers to find vulnerabilities, understand attack vectors through generated code, and verify fixes instantly.
</p>

---

## Installation

```bash
cargo install --git https://github.com/Ramprasad4121/anchor-sentinel
```

That's it. The tool is now available globally.

---

## Usage

### Scan a project
```bash
anchor-sentinel scan . # Scan the entire project
anchor-sentinel scan ./programs # Scan a specific directory
```

### Generate exploit POCs
```bash
anchor-sentinel scan . --generate-poc --output ./pocs # Generate POCs for the entire project
anchor-sentinel scan ./programs --generate-poc --output ./pocs # Generate POCs for a specific directory
```

### Filter by severity
```bash
anchor-sentinel scan ./programs --severity high
```

### Run specific detectors
```bash
anchor-sentinel scan ./programs --only V001,V003
```

### Compare two versions (Diff)
```bash
anchor-sentinel diff ./v1 ./v2
```

### Add to CI/CD (GitHub Actions)
```bash
anchor-sentinel init
```
This generates `.github/workflows/sentinel.yml` for automatic PR scanning.

---

## Vulnerability Detectors

| ID | Name | Severity |
|----|------|----------|
| V001 | Missing Signer Check | Critical |
| V002 | Missing Owner Check | High |
| V003 | Integer Overflow | High |
| V004 | PDA Seed Collision | High |
| V005 | Reinitialization | Critical |
| V006 | Unsafe CPI | Critical |
| V007 | Token-2022 Risks | High |

---

## License

GPL-3.0 - See [License](./License)
