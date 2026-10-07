# Azure Cloud Security Lab — Misconfiguration Hunt (CIS-Mapped)

> I deployed a set of intentionally-insecure Azure resources, detected every misconfiguration against the CIS Microsoft Azure Foundations Benchmark using PowerShell 7 and the Microsoft Graph/Azure REST APIs, then remediated each one back to a secure baseline and verified the fix — a full **deploy → detect → remediate → verify** loop, with before/after evidence.

**Tech:** PowerShell 7 · Az PowerShell (Accounts, Resources, Storage, Network) · `Invoke-AzRestMethod` · Microsoft Defender for Cloud (foundational CSPM) · Azure Storage · Azure Networking (NSG) · CIS Azure Foundations Benchmark v2.1.0 · NIST 800-53 Rev 5 · MITRE ATT&CK

---

## Problem Statement (Situation)
Cloud misconfigurations — not zero-days — are the leading cause of cloud data exposure. Public storage endpoints and management ports left open to the internet are scanned and exploited within minutes of going live. Security teams need to be able to **find these misconfigurations programmatically, map them to a recognized benchmark, and prove they were remediated** — not just eyeball a portal.

## Objective (Task)
Build a repeatable lab that:
1. Deploys deliberately-vulnerable Azure resources (insecure storage account + an NSG exposing RDP to the internet).
2. Detects each misconfiguration and maps it to its CIS control.
3. Remediates every finding back to a secure baseline, safely (dry-run first).
4. Produces reproducible before/after evidence suitable for an audit or a portfolio.

## Tools & Environment
- **PowerShell 7** on Windows
- **Az PowerShell SDK** — `Az.Accounts`, `Az.Resources`, `Az.Storage`, `Az.Network`
- **`Invoke-AzRestMethod`** — calls the Microsoft.Security REST API directly (no extra module) for Defender for Cloud Secure Score + assessments
- **Microsoft Defender for Cloud** — free foundational CSPM tier
- **Azure free-trial subscription** (subscription ID sanitized throughout)

---

## Step-by-Step Breakdown (Action)

### 1. Plant the vulnerabilities — `deploy-misconfig-lab.ps1`
Created a resource group (`RG-MisconfigLab`) containing:
- A **storage account** with: secure-transfer (HTTPS-only) **off**, min TLS set to 1.0 (requested), **public blob access on**, **public network access enabled**.
- An **NSG** (`nsg-misconfig`) with an inbound rule allowing **RDP (3389) from `*`** (the entire internet).

Each planted misconfiguration is annotated in-script with the CIS control it violates. The script supports `-WhatIf` and `-Remove` for clean teardown.

> **Honest finding — Azure's secure-by-default wins one:** the request to set minimum TLS to 1.0 was **silently overridden by Azure**, which now enforces TLS 1.2 as the floor (`WARNING: TLS 1.0 and TLS 1.1 are retired`). I documented this as *attempted → platform-blocked* rather than claiming a misconfiguration that doesn't exist. Knowing where the platform protects you is as important as knowing where it doesn't.

### 2. Detect + map to CIS — `scan-azure-misconfig.ps1`
Because the subscription was brand-new, Defender for Cloud's first assessment pass hadn't completed (provider still `Registering`, 0 assessed resources). Rather than block on Defender's crawl, I used **deterministic config-level detection** as the primary evidence source — reading each resource's live configuration and mapping it to its CIS control. This is *stronger* for a portfolio: anyone can re-run it and get identical results.

The script pulls the Secure Score and all Defender assessments via `Invoke-AzRestMethod` (so the Defender/CSPM layer folds in automatically once the crawl finishes), filters to the lab resource group, flags every `Unhealthy` finding, and maps it to a CIS control — writing a timestamped CSV to `evidence/`.

### 3. Remediate safely — `remediate-misconfig.ps1`
- Auto-discovers the randomized storage account name (no hard-coding).
- Hardens storage: **HTTPS-only on, TLS 1.2, public blob off, public network disabled**.
- **Removes** the internet-facing RDP rule from the NSG.
- Gated behind `SupportsShouldProcess` / `ConfirmImpact='High'`, so `-WhatIf` previews every change before anything is touched.
- Ends with a **verification pass** that re-reads both resources and prints the post-remediation state.

---

## Visual Evidence
*All screenshots captured during the live run (subscription ID redacted).*

- **Before:** config check showing `HTTPS-only: False`, `Public blob: True`, `Public network: Enabled`, and the `Allow-RDP-FromInternet` rule with `SourceAddressPrefix {*}` / port `{3389}`.
- **After:** same check showing `HTTPS-only: True`, `Public blob: False`, `Public network: Disabled`, and the RDP rule **removed**.

Machine-readable evidence: [`evidence/misconfig-scan-before-*.csv`](evidence/) → 4 FAIL · [`evidence/misconfig-scan-after-*.csv`](evidence/) → all PASS.

---

## Final Results (Result)

| # | Misconfiguration | CIS Control¹ | NIST 800-53 | MITRE ATT&CK | Before → After |
|---|---|---|---|---|---|
| 1 | Secure transfer (HTTPS) disabled | **3.1** Secure transfer required | SC-8 | T1040 | ❌ False → ✅ **True** |
| 2 | Public blob / anonymous access on | **3.x** Blob anonymous access disabled | AC-3, AC-22 | T1530 | ❌ True → ✅ **False** |
| 3 | Public network access enabled | **3.x** Default network rule = Deny | SC-7 | T1190 | ❌ Enabled → ✅ **Disabled** |
| 4 | RDP (3389) open to the internet | **6.1** RDP from internet restricted | SC-7 | T1133 / T1021.001 | ❌ Allow `*` → ✅ **rule removed** |
| — | Min TLS 1.0 (attempted) | **3.x** Minimum TLS 1.2 | SC-8(1) | — | Platform-enforced to TLS 1.2 |

**Outcome:** 4 live, CIS-mapped misconfigurations identified and **100% remediated**; verification confirmed all 5 settings at a secure baseline (including full removal of the open RDP rule). Entire loop is scripted and reproducible.

¹ *Control numbers per CIS Microsoft Azure Foundations Benchmark v2.1.0; exact sub-numbers for storage controls vary by benchmark version — verify against your tenant's assigned benchmark.*

---

## Lessons Learned & What I'd Improve Next (Reflection)
- **Secure-by-default is real.** Azure refusing to set TLS below 1.2 was a live reminder that the platform closes some footguns for you — but only some. The RDP-to-the-world rule planted without complaint.
- **Deterministic detection beats waiting on a dashboard.** Config-level reads gave instant, reproducible evidence while Defender's CSPM crawl was still spinning up. In production I'd use *both*: config checks for fast CI/CD gating, Defender/CSPM for continuous drift detection.
- **Next iterations:** (1) wrap the config checks as an **Azure Policy** `deny`/`audit` initiative so misconfigs are blocked at deploy time, not caught after; (2) add **remediation-as-code** via Policy `DeployIfNotExists`; (3) extend coverage to Key Vault, SQL, and managed identities; (4) capture the Defender Secure Score delta (before/after) once the CSPM crawl completes, as a second evidence layer.

---

## Skills Demonstrated
- Cloud security posture management (CSPM) and benchmark-based auditing
- Mapping findings to **CIS**, **NIST 800-53**, and **MITRE ATT&CK**
- Infrastructure + remediation scripting in PowerShell 7 against the Az SDK and Azure REST API
- Safe change management (`-WhatIf` / `ShouldProcess`), idempotent teardown, and verification
- Producing audit-grade before/after evidence

## Repo Structure
```
azure-cloud-security/
├── README.md
├── scripts/
│   ├── deploy-misconfig-lab.ps1      # plant the vulnerable resources (-WhatIf / -Remove)
│   ├── scan-azure-misconfig.ps1      # detect -> map to CIS -> CSV evidence
│   └── remediate-misconfig.ps1       # harden to secure baseline (-WhatIf) + verify
└── evidence/
    ├── misconfig-scan-before-*.csv   # 4 FAIL baseline
    └── misconfig-scan-after-*.csv    # all PASS
```
