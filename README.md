# Anchor-Sentinel

**Static security analyzer for Solana Anchor smart contracts.**

Detects vulnerabilities like missing signer checks, integer overflows, unsafe CPIs, and Token-2022 risks. Generates runnable TypeScript exploit POCs.

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
