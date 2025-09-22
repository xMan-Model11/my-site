# Project: MFA Replay Attack Emulation & Defense

## Overview

This project demonstrates my ability to design and execute a **threat emulation lab** to evaluate the effectiveness of Multi-Factor Authentication (MFA) controls against modern adversary techniques. Specifically, I replicated a **phishing and session replay attack** using an adversary-in-the-middle (AiTM) approach.

By capturing and replaying MFA-protected session tokens, I highlighted weaknesses in session management that can undermine otherwise strong MFA implementations. The project not only showcases offensive skills (threat replication) but also defensive thinking (control evaluation and mitigation).

---

## Project Goals

* **Threat Emulation:** Recreate a realistic adversary-in-the-middle phishing scenario targeting MFA-enabled accounts.
* **Security Control Testing:** Assess whether the target service’s MFA implementation was resilient against session token replay.
* **Defensive Insight:** Derive lessons learned and propose mitigations to strengthen identity and access security.
* **Technical Proficiency:** Demonstrate skill across domains—cloud infrastructure, DNS, adversary tooling, and hands-on replay of session artifacts.

---

## Tools & Infrastructure

The following components were deployed to build a realistic test environment:

* **Evilginx2** – Used as the reverse proxy to transparently capture credentials and session tokens.
* **Google Cloud Platform (GCP)** – Hosted the Evilginx2 server on a VM with a public IP to emulate a real adversary infrastructure setup.
* **Namecheap** – Provided the registered phishing domain used for the lure.
* **Cloudflare DNS** – Managed DNS records, pointing the phishing domain to the Evilginx2 server (common in real-world adversary tradecraft).
* **Kali Linux** – Controlled the Evilginx2 instance and executed session replay testing.
* **Cookie Editor (Browser Extension)** – Allowed for injection of stolen session cookies to bypass MFA protections.

---

## Attack & Defense Methodology

The lab followed a structured, step-by-step methodology:

1. **Infrastructure Provisioning**

   * Deployed an Evilginx2 server on GCP.
   * Registered a phishing domain and routed it through Cloudflare for DNS resolution.
   * Configured an **A record** to point traffic to the GCP instance.

2. **Phishing Lure Creation**

   * Evilginx2 generated a phishing lure that cloned a legitimate sign-in page.
   * Test user clicked the lure and proceeded through username, password, and MFA entry.

3. **Credential & Token Capture**

   * Evilginx2, acting as a transparent proxy, captured:

     * Username & password.
     * MFA one-time passcode.
     * Authentication tokens and session cookies issued by the real service.

4. **Session Replay**

   * Captured session cookies were exported.
   * On a separate Kali machine, cookies were injected into a clean browser session using Cookie Editor.
   * The browser was able to impersonate the victim, fully bypassing MFA and gaining access.

**Attack Flow Diagram**

  [Victim Browser]
         |
  (clicks phishing URL / submits credentials + MFA)
         |
         v
  +-------------------+
  |   Evilginx2 (AiTM)|
  |  Reverse Proxy    |
  | - Forwards traffic|
  | - Captures creds  |
  | - Captures cookies|
  +-------------------+
         |
 (forwards to legitimate service)
         v
  [Real Service / IdP]
         |
 (issues session cookies / tokens)
         |
         v
  <-- captured tokens stored on Evilginx2 -->
         |
         v
  [Attacker Workspace]
   (export cookies -> import with Cookie Editor)
         |
 (inject stolen cookies into browser)
         v
  [Attacker Browser]
  (impersonates victim — MFA bypass via replay)



---

## Findings

* The tested service’s MFA implementation was **susceptible to session replay attacks**.
* Once the attacker obtains valid session tokens, MFA is effectively neutralized until those tokens expire or are revoked.
* This highlights the importance of **robust session management** as a critical layer of defense beyond initial authentication.

---

## Recommended Mitigations

* **Session Binding** – Bind tokens to device/browser fingerprints or client IPs to prevent cross-context replay.
* **Short Session Lifespans** – Reduce session validity windows and enforce frequent token refreshes.
* **Context-Aware MFA** – Re-prompt for MFA when login context changes (device, location, or IP).
* **Continuous Authentication** – Adopt adaptive risk-based authentication that continuously evaluates session trust.

---

## Key Takeaways

This project demonstrates:

* **Hands-on Red Team Skills** – Deploying adversary infrastructure, executing phishing and session hijacking.
* **Blue Team Insight** – Identifying mitigation strategies rooted in modern identity defense.
* **Full-Scope Thinking** – Bridging offensive testing with defensive recommendations, showcasing ability to emulate adversaries *and* strengthen controls.

---

🔒 **This project highlights my ability to perform controlled adversary simulations that inform stronger security architectures—transforming offensive findings into defensive value.**

---
