---
title: Tools
layout: default
permalink: /tools/
---

# Tools

Collection of scripts and utilities for detection, hunting, and automation. Each tool lives in its own folder with a README that includes usage, examples, and verification hashes.

- [Home](../index.md)

---

## How this directory is organized
- `powershell/` — PowerShell scripts with usage examples and sample output.  
- `python/` — Python utilities and scrapers.  
- `cql/` — CrowdStrike CQL queries and test cases.  
- `hashes.md` — SHA256 hashes and verification instructions.

---

## Included Tools

### PowerShell Scripts
- [**FileLocator**](tools/powershell/FileLocator/find_file.ps1) — `tools/powershell/FileLocator/find_file.ps1`  
  **Purpose**: Search file systems for suspicious filenames and output CSV.  
  **Quick usage**:
  ```powershell
  .\find_file.ps1 -FileName "invoice.pdf"
  ```
  **SHA256**: 975354cfb5b4066a815f898e67088dffae13606be21306832a16c1facf389bc5

- [**App Hunting Tool**](tools/powershell/AppHuntingRemoval_DisplayName) — `powershell/AppHuntingRemoval_DisplayName/AppHuntingRemoval_DisplayName.ps1`   
  **Purpose**: Enumerate installed apps and detect known malicious display names.  
  **Quick usage**:
  ```powershell
  Edit script with target app display name
  ```
  **SHA256**: 988b02c06a0808396b8c268f4265f0199ca0c76b424e3514bbf405db86a7c8f9

- [**Get AD Group Members Filtered by OU**](tools/powershell/AD/get-ADGroupMembersFilteredbyOU.ps1) — `powershell/AD/get-ADGroupMembersFilteredbyOU.ps1`   
  **Purpose**: Query AD group membership scoped to an OU. 
  **Quick usage**:
  ```powershell
  Edit the top of script 
  $GroupName = "Domain Admins"
  $OuDn      = "OU=Staff,OU=Users,DC=corp,DC=example,DC=com"
  .\Get-ADGroupMembersByOU.ps1
  ```
  **SHA256**: 620f0191c1bb93878f411c1ac46f29c295c08eda97cc22e764583f1bad0c22c0

- [**Get AD Users Groups by UPN**](tools/powershell/AD/get-ADGroupsFromUPNs.ps1) — `powershell/AD/get-ADGroupsFromUPNs.ps1`   
  **Purpose**: Query AD Users Group Membership scoped to an UPN(s).  
  **Quick usage**:
  ```powershell
  Replace with your list of UPNs
  .\Get-ADUsersGroupsFromUPNs.ps1
  ```
  **SHA256**: 67c2abc28954e265d412ce3673d36d52c006443f1cdd82535a769ef076e8f20e
  
- [**Get AD Attributes by UPN**](tools/powershell/AD/get-adUser-Email-SAMname-JobTitle-Dept-Co-Mgr_by_UPN.ps1) — `powershell/AD/get-adUser-Email-SAMname-JobTitle-Dept-Co-Mgr_by_UPN.ps1`   
  **Purpose**: Query AD Attributes of users scoped to an UPN(s).  
  **Quick usage**:
  ```powershell
  Replace with your list of UPNs
  .\get-adUser-Email-SAMname-JobTitle-Dept-Co-Mgr_by_UPN.ps1
  ```
  **SHA256**: 9d832458f79777376ca6811a2929e7c1fd55256e6c25809c27925789667abcb0


### CrowdStrike Queries
- [**Quick Suspicious DNS Hunting CQL queries**](tools/cql/cqlSuspiciousDnsHunting.cql) — `cql/cqlSuspiciousDnsHunting.cql`  
  **Purpose**: Hunting for anomalous DNS patterns and suspicious domains.  
  **Quick usage**:
  ```CQL
  list of several cql queries when hunting for DNS queries
  ```
  **SHA256**: 51e62e15142589ee8c25b7e34e035a6c84b2b2e6375585c9adbbb52c3d4155ce


### Python Scripts
- [**WebSleuth**](tools/python/curl_scrapper.py) — `python/curl_scrapper.py`  
  **Purpose**: Lightweight web scraping for ctf low-hanging fruit (redacted for public use).  
  **Quick usage**:
  ```Python
  python3 websleuth.py --min-confidence medium
  When prompted, enter the target URL, e.g.:
  Target URL[](https://example.com): example.com
  ```
  **SHA256**: 1dd41c9222fbdc4b398af2db59596118e7cc0fc7af2fa0dad68fc75c48d3eb2c
