#!/usr/bin/env python3
"""
WebSleuth — enhanced version

Author: Xaver I

- Refined regex to reduce FP
- Added per-finding confidence
- Expanded framework fingerprinting (Next.js / React / Vue / Angular / Svelte / Nuxt.js / Remix)
- Added JS file downloading + deep scanning (limit to 20 JS files)
- Improved output: findings grouped + sorted by confidence (high > medium > low), with optional min_confidence filter
"""

import sys
import re
import json
import requests
from typing import Optional
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque
from datetime import datetime, timezone
import argparse  # Added for CLI args like --min-confidence

# ────────────────────────────────────────────────
#  Improved & classified keyword set + confidence
# ────────────────────────────────────────────────
THREAT_PATTERNS = {
    "secrets": {
        "high": [
            r'AKIA[0-9A-Z]{16}',                 # AWS access key (very strong signal)
            r'ASIA[0-9A-Z]{16}',
            r'(?i)sk_live_[0-9a-zA-Z]{24,}',     # Stripe live secret
            r'(?i)sgp_[a-f0-9]{40,}',            # common SendGrid / other services
        ],
        "medium": [
            r'api[_-]?key(?!\s*[:=]\s*["\']?\s*["\'])',  # avoid matching comment-like "api key:"
            r'(?:access|auth|bearer|client)[_-]?(?:token|key|secret)',
            r'(?<!\w)secret(?!\s*[:=])',         # "secret" not in assignment
        ],
        "low": [
            r'secret',
            r'private[_-]?key',
        ]
    },

    "credentials": {
        "high": [],
        "medium": [
            r'(?i)\b(?:password|passwd|pwd)\b(?!\s*[:=]\s*["\']?\s*["\'])',
            r'(?i)\busername\b(?!\s+in\s)',
        ],
        "low": [
            r'(?i)\b(?:login|credential)\b',
        ]
    },

    "cloud": {
        "high": [
            r'AKIA[0-9A-Z]{16}',
            r'ASIA[0-9A-Z]{16}',
        ],
        "medium": [
            r'(?i)aws_access_key_id',
            r'(?i)aws_secret_access_key',
            r'(?i)azure.*?(?:key|token|secret)',
        ],
        "low": [
            r'(?i)(?:gcp|google_cloud|azure)',
        ]
    },

    "pii": {
        "high": [
            r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b',               # SSN
        ],
        "medium": [
            r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',  # email (still noisy)
        ],
        "low": []
    },

    "internal_debug": {
        "high": [],
        "medium": [
            r'\b(?:debug|trace|verbose)\b(?!\s*(?:mode|level))',
            r'\bstaging\b',
            r'\b(?:preprod|uat)\b',
        ],
        "low": [
            r'\bdev\b(?!\w)',                     # avoid device, devtools, develop→dev
            r'\bdevelopment\b(?!\w)',
            r'\btest\b(?!\w(?:ing|ed))',          # avoid testing, tested,ytest,...
            r'\b(?:todo|fixme)\b',
            r'\binternal\b(?!\s*(?:css|style|api))',
        ]
    },

    "security_controls": {
        "high": [
            r'(?i)bearer\s+[a-zA-Z0-9\-._~+/]{20,}=*',   # JWT-ish or real token
        ],
        "medium": [
            r'(?i)x-api-key',
            r'(?i)authorization\s*:\s*basic\s+[a-zA-Z0-9+/=]{8,}',
            r'(?i)csrf[-_]?(?:token)?',
        ],
        "low": [
            r'(?i)jwt',
        ]
    }
}

# ────────────────────────────────────────────────
#  Expanded Framework fingerprints
# ────────────────────────────────────────────────
FRAMEWORK_SIGNATURES = {
    "Next.js": {
        "confidence": "high",
        "indicators": [
            (r'/_next/static/', "path"),
            (r'__NEXT_DATA__', "html"),
            (r'next/router', "js"),
            (r'next/image', "html|js"),
        ]
    },
    "React": {
        "confidence": "medium",
        "indicators": [
            (r'react(?:\.min)?\.js', "path|src"),
            (r'react-dom', "path|src"),
            (r'__REACT_DEVTOOLS_GLOBAL_HOOK__', "js"),
            (r'create-react-app', "html|js"),
        ]
    },
    "Vue": {
        "confidence": "medium",
        "indicators": [
            (r'(?:vue|vue-router|vuex)(?:\.min)?\.js', "path|src"),
            (r'__VUE_DEVTOOLS_', "js"),
            (r'data-v-', "html class"),   # scoped styles
            (r'v-bind|v-on:|v-for', "html"),
        ]
    },
    "Angular": {
        "confidence": "medium",
        "indicators": [
            (r'angular(?:\.min)?\.js', "path|src"),
            (r'ng-app', "html"),
            (r'ng-controller', "html"),
            (r'ng-repeat', "html"),
            (r'ng-if', "html"),
        ]
    },
    "Svelte": {
        "confidence": "medium",
        "indicators": [
            (r'svelte(?:\.min)?\.js', "path|src"),
            (r'__svelte__', "js"),
            (r'svelte/store', "js"),
            (r'onMount', "js"),  # Common Svelte lifecycle
        ]
    },
    "Nuxt.js": {
        "confidence": "high",
        "indicators": [
            (r'/_nuxt/', "path"),
            (r'__NUXT__', "html"),
            (r'nuxt(?:\.min)?\.js', "path|src"),
            (r'vue-router', "js"),  # Often with Vue
        ]
    },
    "Remix": {
        "confidence": "medium",
        "indicators": [
            (r'remix(?:\.min)?\.js', "path|src"),
            (r'@remix-run/', "js"),
            (r'useLoaderData', "js"),
            (r'createRoutesFromElements', "js"),
        ]
    },
    # Add more as needed: Gatsby (/page-data/), etc.
}

def detect_frameworks(html: str, paths: set[str], js_contents: list[str]) -> list[dict]:
    detected = []
    html_lower = html.lower()
    all_js = ' '.join(js_contents).lower()  # Aggregate JS for deeper checks

    for fw, data in FRAMEWORK_SIGNATURES.items():
        score = 0
        evidence = []

        for pat, where in data["indicators"]:
            matched = False
            if where == "path" or where == "path|src":
                if any(re.search(pat, p, re.I) for p in paths):
                    score += 2
                    evidence.append(f"path match: {pat}")
                    matched = True
            if not matched and (where in ("html", "html class") or "html" in where):
                if re.search(pat, html_lower, re.I):
                    score += 1
                    evidence.append(f"html match: {pat}")
                    matched = True
            if not matched and ("js" in where):
                if re.search(pat, all_js, re.I):
                    score += 1
                    evidence.append(f"js match: {pat}")

        if score >= 2:
            detected.append({
                "framework": fw,
                "confidence": data["confidence"] if score > 3 else "medium",
                "score": score,
                "evidence": evidence[:4]  # limit noise
            })

    return sorted(detected, key=lambda x: x["score"], reverse=True)


# ────────────────────────────────────────────────
#  Fetch (now handles JS too)
# ────────────────────────────────────────────────
def fetch_content(url: str, is_js: bool = False) -> Optional[str]:
    try:
        headers = {"User-Agent": "WebSleuth/1.2"}
        if is_js:
            headers["Accept"] = "application/javascript"
        resp = requests.get(url, timeout=7, verify=False, headers=headers)
        resp.raise_for_status()
        return resp.text
    except requests.exceptions.SSLError:
        if url.startswith("https://"):
            try:
                fallback = url.replace("https://", "http://", 1)
                resp = requests.get(fallback, timeout=7, headers=headers)
                resp.raise_for_status()
                print(f"[i] Downgraded to http → {url}")
                return resp.text
            except Exception:
                pass
    except Exception as e:
        print(f"[!] Fetch failed {url}: {e}", file=sys.stderr)
    return None


# ────────────────────────────────────────────────
#  Path extraction
# ────────────────────────────────────────────────
def extract_paths(html: str, base_url: str) -> set[str]:
    soup = BeautifulSoup(html, 'html.parser')
    paths = set()
    base_netloc = urlparse(base_url).netloc

    # Tag-based
    for tag, attr in {
        'a': 'href', 'link': 'href', 'script': 'src',
        'img': 'src', 'form': 'action', 'source': 'src'
    }.items():
        for el in soup.find_all(tag):
            if el.has_attr(attr):
                raw = el[attr].strip()
                if raw and raw.startswith('/') and not raw.startswith('//'):
                    full = urljoin(base_url, raw)
                    if urlparse(full).netloc == base_netloc:
                        paths.add(urlparse(full).path)

    # Inline JS — more conservative
    for script in soup.find_all('script'):
        if not script.string:
            continue
        for q in re.findall(r'''["'](/[^"'\s<>{}[\]()]+)["']''', script.string):
            if '//' not in q or q.startswith('//'):
                continue
            paths.add(q)

    return paths


def is_likely_directory_path(path: str) -> bool:
    p = path.strip('/').split('/')
    return len(p) >= 2 and '.' not in p[-1] and not p[-1].isdigit()


# ────────────────────────────────────────────────
#  Keyword scanner with confidence
# ────────────────────────────────────────────────
def scan_for_keywords(content: str, url: str) -> list[dict]:
    findings = []
    for category, levels in THREAT_PATTERNS.items():
        for conf_level, patterns in levels.items():
            for pat in patterns:
                for m in re.finditer(pat, content, re.IGNORECASE):
                    start = max(m.start() - 50, 0)
                    end   = min(m.end() + 70, len(content))
                    snippet = content[start:end].replace('\n', ' ').strip()
                    findings.append({
                        "url": url,
                        "category": category,
                        "confidence": conf_level,
                        "match": m.group(0),
                        "pattern": pat,
                        "snippet": snippet
                    })
    return findings


# ────────────────────────────────────────────────
#  Main
# ────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="WebSleuth: Web recon tool")
    parser.add_argument("--min-confidence", choices=["high", "medium", "low"], default="low",
                        help="Filter findings to this confidence or higher (default: low)")
    args = parser.parse_args()

    conf_map = {"high": 3, "medium": 2, "low": 1}
    min_conf_num = conf_map[args.min_confidence]

    base_url = input("Target URL[](https://example.com): ").strip()
    if not base_url:
        sys.exit("No URL provided.")

    if not base_url.startswith(('http://', 'https://')):
        base_url = 'https://' + base_url
    if not base_url.endswith('/'):
        base_url += '/'

    max_depth = 3
    max_scans = 60
    max_js_scans = 20  # Limit JS downloads

    queue = deque([('', 0)])
    visited = set()
    discovered_paths = set()
    all_findings = []
    js_contents = []  # For framework detection
    scans = 0
    js_scanned = 0

    print(f"\nStarting WebSleuth → {base_url} (min_conf: {args.min_confidence})\n")

    while queue and scans < max_scans:
        rel_path, depth = queue.popleft()
        target = urljoin(base_url, rel_path)

        if target in visited or depth > max_depth:
            continue

        visited.add(target)
        scans += 1
        print(f"[{scans:2d}] depth {depth} → {target}")

        html = fetch_content(target)
        if not html:
            continue

        # Keyword scan (HTML)
        all_findings.extend(scan_for_keywords(html, target))

        # Path extraction
        new_paths = extract_paths(html, base_url)
        discovered_paths.update(new_paths)

        # Queue likely directories
        for p in new_paths:
            full = urljoin(base_url, p)
            if is_likely_directory_path(p) and full not in visited:
                queue.append((p, depth + 1))

    # ── JS Deep Scan ─────────────────────────────────
    js_paths = [p for p in discovered_paths if p.lower().endswith('.js')]
    print(f"\n[+] Found {len(js_paths)} JS files; scanning up to {max_js_scans}")

    for p in js_paths[:max_js_scans]:
        js_url = urljoin(base_url, p)
        if js_url in visited:
            continue
        visited.add(js_url)
        js_scanned += 1
        print(f"[JS {js_scanned:2d}] → {js_url}")
        js_content = fetch_content(js_url, is_js=True)
        if js_content:
            js_contents.append(js_content)
            all_findings.extend(scan_for_keywords(js_content, js_url))

    # ── Framework detection ───────────────────────────────
    last_html = html if 'html' in locals() else ""  # Use last fetched HTML
    frameworks = detect_frameworks(last_html, discovered_paths, js_contents)

    # ── Filter & Group/Sort Findings ──────────────────────
    conf_num = {"high": 3, "medium": 2, "low": 1}
    filtered_findings = [f for f in all_findings if conf_num[f["confidence"]] >= min_conf_num]
    sorted_findings = sorted(filtered_findings, key=lambda x: (-conf_num[x["confidence"]], x["category"], x["url"]))

    grouped_findings = {"high": [], "medium": [], "low": []}
    for f in sorted_findings:
        grouped_findings[f["confidence"]].append(f)

    # ── Final output ──────────────────────────────────────
    output = {
        "target": base_url,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "pages_scanned": scans,
        "js_scanned": js_scanned,
        "frameworks_detected": frameworks,
        "unique_paths": sorted(discovered_paths),
        "findings": grouped_findings  # Grouped by confidence
    }

    with open("websleuth_results_enhanced.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print("\nScan complete")
    print(f"Pages scanned : {scans} (+ {js_scanned} JS)")
    print(f"Frameworks    : {', '.join(d['framework'] for d in frameworks) or 'none detected'}")
    print(f"Findings      : {len(filtered_findings)} (high: {len(grouped_findings['high'])}, medium: {len(grouped_findings['medium'])}, low: {len(grouped_findings['low'])})")
    print("Results → websleuth_results_enhanced.json")


if __name__ == "__main__":
    main()