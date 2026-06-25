---
title: Tools & Utilities
layout: default
permalink: /tools/
---

# Security Tools & Hunting Utilities

**Practical, battle-tested scripts for detection engineering, threat hunting, and automation.**

These tools were built from real-world incident response and blue-team operations. Each includes:
- Clear usage examples
- Sample output
- SHA256 verification hashes (for integrity)
- Focused READMEs in their folders

**[← Back to Home](../index.md)**

---

## Why These Tools Matter

Hiring managers often ask: *"Can you actually ship useful defensive tooling?"*

This repository is my answer. The tools here have helped:
- Rapidly scope compromised endpoints
- Hunt anomalous behavior at scale
- Automate repetitive AD enumeration and app hunting tasks
- Support detection-as-code workflows

All tools are **open-source friendly**, well-documented, and designed for enterprise environments.

---

## 📂 Directory Structure

- `powershell/` — Windows-focused detection & response scripts
- `python/` — Cross-platform utilities and enrichment tools
- `cql/` — CrowdStrike Falcon LogScale (CQL) hunting queries
- `hashes.md` — Complete SHA256 manifest + verification instructions

---

## Featured Tools

### PowerShell (Windows Defense & Response)

| Tool | Purpose |
|------|--------|
| **[FileLocator](./tools/powershell/FileLocator/find_file.ps1)** | Rapidly hunts file systems for suspicious filenames and patterns (e.g. ransomware notes, phishing attachments). Exports results to CSV for fast triage and reporting. |
| **[App Hunting Tool](./tools/powershell/AppHuntingRemoval_DisplayName/AppHuntingRemoval_DisplayName.ps1)** | Enumerates installed applications and automatically perform cleanup.|
| **[Get AD Group Members Filtered by OU](./tools/powershell/AD/get-ADGroupMembersFilteredbyOU.ps1)** | Performs scoped Active Directory group enumeration limited to specific OUs. Critical for privilege auditing, least-privilege reviews, and identifying over-privileged accounts. |
| **[Get AD Users Groups by UPN](./tools/powershell/AD/get-ADGroupsFromUPNs.ps1)** | Bulk retrieves group membership for lists of users by UPN. Accelerates access reviews, insider threat investigations, and offboarding workflows. |
| **[Get AD Attributes by UPN](./tools/powershell/AD/get-adUser-Email-SAMname-JobTitle-Dept-Co-Mgr_by_UPN.ps1)** | Exports rich user attributes (email, job title, department, manager, etc.) for multiple accounts. Streamlines user risk assessments, access certification, and incident response enrichment. |

### CrowdStrike Falcon (CQL)

| Tool | Purpose | Quick Start |
|------|--------|-------------|
| **[Suspicious DNS Hunting Queries](./tools/cql/cqlSuspiciousDnsHunting.cql)** | Ready-to-use queries for anomalous DNS, living-off-the-land, and suspicious domains | Load into LogScale and customize |

### Python

| Tool | Purpose | Quick Start |
|------|--------|-------------|
| **[WebSleuth](./tools/python/curl_scrapper.py)** | Lightweight web scraping & enrichment (redacted for public CTF/low-hanging fruit use) |

---

## Next Steps & Verification

1. Clone the repo
2. Verify file integrity: See [`hashes.md`](hashes.md)
3. Check individual tool folders for detailed READMEs, examples, and sample output

**All tools are MIT licensed** and free to use/modify.

---

**Questions or want to see these in action?** Feel free to open an issue or reach out — I'm always happy to discuss detection engineering, threat hunting, or how these tools fit into a mature security program.

---

*Last updated: {{ site.time | date: "%B %d, %Y" }}*
