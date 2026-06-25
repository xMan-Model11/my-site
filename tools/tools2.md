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

| Tool | Purpose | Quick Start | SHA256 |
|------|--------|-------------|--------|
| **[FileLocator](tools/powershell/FileLocator/find_file.ps1)** | Fast filesystem hunting for suspicious filenames/patterns → CSV output | `.\find_file.ps1 -FileName "invoice.pdf"` | `975354cfb5b4...` |
| **[App Hunting Tool](tools/powershell/AppHuntingRemoval_DisplayName/AppHuntingRemoval_DisplayName.ps1)** | Enumerate installed software and flag known malicious display names | Edit target app name in script | `988b02c06a08...` |
| **[Get AD Group Members Filtered by OU](tools/powershell/AD/get-ADGroupMembersFilteredbyOU.ps1)** | Scoped AD group enumeration (great for privilege auditing) | Set `$GroupName` and `$OuDn` | `620f0191c1bb...` |
| **[Get AD Users Groups by UPN](tools/powershell/AD/get-ADGroupsFromUPNs.ps1)** | Bulk group membership lookup from list of UPNs | Replace UPN list in script | `67c2abc28954...` |
| **[Get AD Attributes by UPN](tools/powershell/AD/get-adUser-Email-SAMname-JobTitle-Dept-Co-Mgr_by_UPN.ps1)** | Rich user attribute export (email, title, manager, etc.) | Replace UPN list in script | `9d832458f797...` |

### CrowdStrike Falcon (CQL)

| Tool | Purpose | Quick Start |
|------|--------|-------------|
| **[Suspicious DNS Hunting Queries](tools/cql/cqlSuspiciousDnsHunting.cql)** | Ready-to-use queries for anomalous DNS, living-off-the-land, and suspicious domains | Load into LogScale and customize | `51e62e151425...` |

### Python

| Tool | Purpose | Quick Start | SHA256 |
|------|--------|-------------|--------|
| **[WebSleuth](tools/python/curl_scrapper.py)** | Lightweight web scraping & enrichment (redacted for public CTF/low-hanging fruit use) | `python3 websleuth.py --min-confidence medium` | `1dd41c9222fb...` |

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
