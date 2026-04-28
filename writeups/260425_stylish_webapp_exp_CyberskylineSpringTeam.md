``` Stylish Web App Exploitation Challenge
---
title: Security Audit - Libre Marketing & Design Website
date: 2026-04-25
categories: [Security Research, CTF Write-ups]
tags: [web-security, less-css, file-disclosure, client-side-vulnerability, ctf]
---

### Security Audit Write-up: Libre Marketing & Design Website

**Challenge Overview**  
A colleague built a marketing website and requested a security review. The scope was limited to HTTPS only. The site appeared to be a clean, static single-page marketing site at first glance.

#### Q1 – Hidden Route (10 points)

**Finding:** `/theme-playground`

**How it was discovered:**  
While auditing the site, I checked `/robots.txt` and found the following entry:

```txt
User-Agent: *
Disallow: /theme-playground
```

This revealed a developer-only page that was intentionally hidden from search engines and crawlers but remained publicly accessible.

#### Q2 – Transpiler Tool (10 points)

**Tool:** `less`

On the `/theme-playground` page, the loaded `main.js` file contained a configuration object for the CSS preprocessor:

```javascript
less = {
  env: "production",
  relativeUrls: false,
  async: false,
  javascriptEnabled: true
}
```

This confirmed that the site was using the **Less** CSS preprocessor (package name: `less`).

#### Q3 – Compilation Location (10 points)

**Answer:** `client side`

The playground page used Alpine.js to send raw CSS input to the `/update-css` endpoint. The response (compiled CSS) was then dynamically injected into the page via JavaScript. All transpilation happened in the browser.

#### Q4 – Vulnerable Setting (20 points)

**Vulnerable configuration:** `javascriptEnabled: true`

This setting enables inline JavaScript execution inside Less code using backticks (`` ` ``). While intended for advanced features, it significantly increases the attack surface when user input is processed by the Less compiler. Even though direct JavaScript evaluation payloads were rejected by the parser in this instance, leaving this option enabled in a production-like environment represents a dangerous misconfiguration.

#### Q5 – Flag Retrieval (50 points)

**Method:** Arbitrary file read via Less `@import`

Because the `/update-css` endpoint accepted arbitrary Less code and processed it client-side with the provided configuration, I was able to abuse the `@import` directive to read sensitive files on the server.

**Exploit Payload:**

```less
@import (inline) "/flag.txt";
```

**Result:**  
The Less compiler treated `/flag.txt` as a file to import and inline. The contents of the flag file were returned in the compiled CSS response and became visible on the page (or in the network response).

This worked because:
- User-controlled input was passed directly to the Less compiler.
- The compiler had permission to read files from the web root (or was able to resolve absolute paths).
- The `(inline)` modifier caused the file content to be embedded directly into the output CSS instead of being referenced as a URL.

---

### Key Takeaways & Lessons Learned

1. **Never expose developer/playground pages in production**  
   Even if hidden via `robots.txt`, they can still be discovered and abused.

2. **CSS preprocessors can be dangerous when user input is involved**  
   Tools like Less, Sass, and Stylus are powerful, but processing untrusted input with them can lead to file disclosure, SSRF, or (when `javascriptEnabled: true`) arbitrary JavaScript execution.

3. **The `@import (inline)` technique**  
   When a CSS preprocessor accepts user-controlled input, `@import (inline)` is a reliable way to read local files if path resolution is not properly restricted.

4. **Defense Recommendations**
   - Disable dangerous options like `javascriptEnabled` in production.
   - Sanitize or whitelist allowed CSS/LESS input.
   - Run the preprocessor in a sandbox or with strict file system permissions.
   - Avoid exposing any compilation playgrounds or admin tools publicly.
   - Use Content Security Policy (CSP) and proper file permissions on the server.

5. **Why this mattered**  
   A seemingly harmless "theme playground" feature allowed full read access to sensitive files on the server (`/flag.txt`). This highlights how client-side features can still impact server security when they interact with backend resources.

---

### Tools & Techniques Used

- Manual inspection of `robots.txt`
- Browser DevTools (Network tab + Sources tab)
- Source code analysis of `main.js`
- Less `@import (inline)` file read technique

---

**Impact Summary**  
This vulnerability demonstrated a classic case of **insecure user-controlled input processed by a powerful compiler**, resulting in arbitrary file disclosure on the server. Even though the transpilation occurred client-side, the misconfiguration allowed attackers to read sensitive files hosted on the web server.

---

*This write-up is part of my security research and CTF challenge portfolio.*
```
