#!/usr/bin/env python3
"""
Generate "indicator" (weak-signal) WAF rules and append them to all_rules.json.

Philosophy (anomaly scoring, ModSecurity-CRS style):
  Each indicator is a *sign* of attack, not a full signature. Alone it is
  (near) harmless; several together accumulate score and cross the block
  threshold. Partial accumulations land in the ML gray zone for adjudication.

Scoring contract (DO NOT change casually — calibrated against thresholds):
  Every indicator uses action.score = 2. The TIER is set purely by severity,
  whose fixed multiplier yields the effective contribution:
      low    x0.5  -> 1.0 pt   (very weak; can appear in benign traffic)
      medium x1.0  -> 2.0 pt   (moderately suspicious)
      high   x1.5  -> 3.0 pt   (strong sign, still not a full signature)

  With block=5.0, challenge=4.0, ML gray zone = [3.0, 5.0):
      1 medium (2.0)            -> ALLOW
      2 medium (4.0)            -> gray -> ML
      3 medium (6.0)            -> BLOCK
      1 high   (3.0)            -> gray -> ML
      1 high + 1 medium (5.0)   -> BLOCK
  i.e. exactly the "3 medium = block, 2 = gray->ML, 1 = allow" behavior.

Idempotent: re-running replaces the IND-* block, never duplicates it.
"""
import json, sys, os

RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "configs", "rules", "all_rules.json")

# Common transform chains
T_DEC = ["url_decode", "lowercase"]              # decode + fold case (most payload checks)
T_HTML = ["url_decode", "html_decode", "lowercase"]  # XSS: also undo HTML entities
T_RAW = ["lowercase"]                            # keep residual encodings (evasion checks)
T_PATH = ["url_decode", "lowercase", "normalize_path"]

PAYLOAD = ["args", "body", "uri"]                # where user payload lives
URLONLY = ["args", "query", "uri"]               # URL-borne (less benign HTML noise)


def rule(rid, cat, sev, desc, inspect, transforms, patterns, fam, logic="any"):
    """Build one indicator rule. log=True only for medium/high to limit noise."""
    return {
        "id": rid,
        "version": "2.0",
        "enabled": True,
        "info": {
            "category": cat,
            "severity": sev,
            "description": desc,
            "tags": ["indicator", "ind:" + fam, "anomaly-scoring"],
        },
        "inspect": [{"source": s} for s in inspect],
        "transforms": transforms,
        "detect": {"logic": logic, "patterns": patterns},
        "action": {
            "score": 2,
            "labels": ["indicator", "ind:" + fam],
            "log": sev in ("medium", "high"),
        },
    }


def rx(value, flags=""):
    p = {"type": "regex", "value": value}
    if flags:
        p["flags"] = flags
    return p


def words(*vals):
    return {"type": "wordlist", "values": list(vals)}


def contains(value):
    return {"type": "contains", "value": value}


IND = []

# =====================================================================
# A. XSS indicators  (category xss)
# =====================================================================
IND += [
    rule("IND-XSS-001-ANGLE-TAG", "xss", "low",
         "HTML tag opener in payload (weak XSS sign)",
         URLONLY, T_HTML, [rx(r"<\s*/?\s*[a-z][a-z0-9]*")], "xss"),
    rule("IND-XSS-002-SCRIPT-WORD", "xss", "low",
         "Bare word 'script' in payload (weak XSS sign)",
         PAYLOAD, T_HTML, [rx(r"\bscript\b")], "xss"),
    rule("IND-XSS-003-EVENT-HANDLER", "xss", "medium",
         "Inline event handler (onerror=, onload=, ...)",
         PAYLOAD, T_HTML, [rx(r"\bon[a-z]{3,15}\s*=")], "xss"),
    rule("IND-XSS-004-JS-SCHEME", "xss", "medium",
         "javascript:/vbscript:/data:text-html scheme",
         PAYLOAD, T_HTML, [words("javascript:", "vbscript:", "data:text/html")], "xss"),
    rule("IND-XSS-005-SINK-FN", "xss", "medium",
         "JS sink / exfil function in payload",
         PAYLOAD, T_HTML,
         [words("alert(", "prompt(", "confirm(", "eval(",
                "document.cookie", "fromcharcode", "settimeout(")], "xss"),
    rule("IND-XSS-006-HTML-ENTITY", "xss", "low",
         "Numeric/hex HTML entity encoding (evasion sign)",
         URLONLY, T_RAW, [rx(r"&#x?[0-9a-f]{1,6};?")], "xss"),
]

# =====================================================================
# B. SQLi indicators  (category sqli)
# =====================================================================
IND += [
    rule("IND-SQLI-001-QUOTE-OP", "sqli", "low",
         "Quote adjacent to SQL operator (weak SQLi sign)",
         PAYLOAD, T_DEC,
         [rx(r"['\"`]\s*((or|and|union|select|where)\b|=|--|#|\|\||\)\s*(--|#|;))")], "sqli"),
    rule("IND-SQLI-002-KEYWORD-COMBO", "sqli", "low",
         "Two SQL keywords co-occurring",
         PAYLOAD, T_DEC,
         [rx(r"\b(select|union|insert|update|delete)\b[\s\S]{0,60}\b(from|into|where|table|values|set)\b")],
         "sqli"),
    rule("IND-SQLI-003-META-FN", "sqli", "medium",
         "SQL metadata / dump function",
         PAYLOAD, T_DEC,
         [words("information_schema", "@@version", "version()", "database()",
                "concat(", "group_concat", "load_file", "into outfile",
                "into dumpfile", "xp_cmdshell")], "sqli"),
    rule("IND-SQLI-004-TAUTOLOGY", "sqli", "medium",
         "Boolean tautology (or 1=1 style)",
         PAYLOAD, T_DEC,
         [rx(r"\b(or|and)\b\s*['\"(]?\s*\d+\s*(=|<>|<|>|like)\s*\d+")], "sqli"),
    rule("IND-SQLI-005-TIME-FN", "sqli", "medium",
         "Time-based blind SQLi function",
         PAYLOAD, T_DEC,
         [words("sleep(", "benchmark(", "pg_sleep", "waitfor delay", "dbms_pipe")], "sqli"),
    rule("IND-SQLI-006-COMMENT", "sqli", "low",
         "SQL comment marker (--, #, /* */)",
         PAYLOAD, T_DEC, [rx(r"(--[\s\-]|/\*!?|\*/|#\s*$)")], "sqli"),
]

# =====================================================================
# C. LFI / path traversal indicators  (category lfi)
# =====================================================================
IND += [
    rule("IND-LFI-001-DOTDOT", "lfi", "low",
         "Directory traversal sequence (../ or ..\\)",
         PAYLOAD, T_DEC, [rx(r"\.\.[\\/]")], "lfi"),
    rule("IND-LFI-002-ENCODED-DOTDOT", "lfi", "medium",
         "Encoded/obfuscated traversal (evasion)",
         PAYLOAD, T_RAW,
         [rx(r"(%2e%2e|%252e|\.\.%2f|\.\.%5c|%c0%ae|%c1%9c)")], "lfi"),
    rule("IND-LFI-003-SENSITIVE-PATH", "lfi", "medium",
         "Reference to sensitive system file",
         PAYLOAD, T_PATH,
         [words("/etc/passwd", "/etc/shadow", "/etc/hosts", "/proc/self",
                "win.ini", "boot.ini", "/windows/system32")], "lfi"),
    rule("IND-LFI-004-PHP-WRAPPER", "lfi", "medium",
         "PHP/stream wrapper scheme",
         PAYLOAD, T_DEC,
         [words("php://", "file://", "expect://", "phar://", "zip://",
                "data://", "glob://")], "lfi"),
    rule("IND-LFI-005-NULLBYTE", "lfi", "medium",
         "Null-byte injection (extension/path truncation)",
         PAYLOAD, T_RAW, [rx(r"(%00|%2500|\x00)")], "lfi"),
    rule("IND-LFI-006-ABS-PATH", "lfi", "low",
         "Absolute filesystem path in a parameter",
         ["args", "query"], T_DEC,
         [rx(r"(^|[?&=/])(/(etc|var|proc|root|home|usr|tmp)/|[a-z]:\\)")], "lfi"),
]

# =====================================================================
# D. RCE / command injection indicators  (category rce)
# =====================================================================
IND += [
    rule("IND-RCE-001-METACHAR", "rce", "low",
         "Shell metacharacter chain (||, &&, $(), backtick, ;cmd)",
         PAYLOAD, T_DEC,
         [rx(r"(\|\||&&|\$\(|`|;\s*(cat|ls|id|nc|sh|bash|wget|curl|rm|cp|mv|chmod|echo|ping|python|perl)\b)")],
         "rce"),
    rule("IND-RCE-002-CMD-COMMON", "rce", "low",
         "Common network/download command token",
         PAYLOAD, T_DEC,
         [rx(r"\b(wget|curl|nc|netcat|ping|telnet|ftp)\s")], "rce"),
    rule("IND-RCE-003-CMD-RECON", "rce", "medium",
         "Recon / shell command (whoami, uname, /bin/sh, ...)",
         PAYLOAD, T_DEC,
         [words("whoami", "uname -", "cat /etc", "/bin/sh", "/bin/bash",
                "powershell", "certutil", "nslookup", "/etc/passwd")], "rce"),
    rule("IND-RCE-004-CMD-SUBST", "rce", "medium",
         "Command substitution ($(...), `...`, ${...})",
         PAYLOAD, T_DEC, [rx(r"(\$\([^)]*\)|`[^`]+`|\$\{[^}]*\})")], "rce"),
    rule("IND-RCE-005-PHP-FN", "rce", "medium",
         "Dangerous PHP execution function",
         PAYLOAD, T_DEC,
         [words("system(", "exec(", "passthru(", "shell_exec", "popen(",
                "proc_open", "assert(", "base64_decode(", "call_user_func")], "rce"),
    rule("IND-RCE-006-PIPE-SHELL", "rce", "low",
         "Pipe into a shell interpreter",
         PAYLOAD, T_DEC, [rx(r"\|\s*(sh|bash|zsh|cmd|powershell)\b")], "rce"),
]

# =====================================================================
# E. SSRF indicators  (category ssrf)
# =====================================================================
IND += [
    rule("IND-SSRF-001-INTERNAL-IP", "ssrf", "medium",
         "Internal / loopback IP reference",
         ["args", "query", "body"], T_DEC,
         [rx(r"(127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254|"
             r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
             r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})")], "ssrf"),
    rule("IND-SSRF-002-URL-SCHEME", "ssrf", "low",
         "URL embedded in a parameter value",
         ["args", "query"], T_DEC,
         [rx(r"\b(https?|ftp|gopher|dict|ldap|file)://")], "ssrf"),
    rule("IND-SSRF-003-CLOUD-META", "ssrf", "medium",
         "Cloud metadata endpoint reference",
         ["args", "query", "body", "uri"], T_DEC,
         [words("169.254.169.254", "metadata.google", "/latest/meta-data",
                "/computemetadata", "metadata.azure")], "ssrf"),
]

# =====================================================================
# F. Generic / heuristic indicators
# =====================================================================
IND += [
    rule("IND-GEN-001-NULL-BYTE", "custom", "low",
         "Null byte anywhere in payload",
         PAYLOAD, T_RAW, [rx(r"(%00|%2500)")], "generic"),
    rule("IND-GEN-002-OVER-ENCODING", "custom", "low",
         "Excessive percent-encoding (obfuscation)",
         PAYLOAD, T_RAW, [rx(r"(%[0-9a-f]{2}){8,}")], "generic"),
    rule("IND-GEN-003-HEX-OBFUSCATION", "custom", "low",
         "Hex / unicode escape obfuscation",
         PAYLOAD, T_DEC, [rx(r"(\\x[0-9a-f]{2}){4,}|(\\u[0-9a-f]{4}){3,}")], "generic"),
    rule("IND-GEN-004-TEMPLATE-EXPR", "rce", "medium",
         "Template-injection expression ({{...}}, ${...}, <%...%>)",
         PAYLOAD, T_DEC,
         [rx(r"(\{\{.{0,60}\}\}|\$\{.{0,60}\}|<%.{0,60}%>|#\{.{0,60}\})")], "generic"),
    rule("IND-GEN-005-SCAN-PATH", "scanner", "low",
         "Probe path for sensitive file/admin endpoint",
         ["uri"], T_PATH,
         [words(".git/", ".env", ".htaccess", ".htpasswd", "wp-admin",
                "phpmyadmin", "/.svn", "/.aws", "/backup", ".sql", ".bak")], "generic"),
    rule("IND-GEN-006-SUSPICIOUS-UA", "scanner", "low",
         "Scripting/automation User-Agent token",
         ["header"], ["lowercase"],
         [words("python-requests", "curl/", "go-http-client", "java/",
                "libwww", "okhttp", "wget/", "scrapy")], "generic"),
]
# attach the header name for the UA rule
IND[-1]["inspect"] = [{"source": "header", "name": "User-Agent"}]


def main():
    path = os.path.normpath(RULES_PATH)
    with open(path, "r", encoding="utf-8") as f:
        existing = json.load(f)

    # Drop any previously-generated indicator rules (idempotent re-run).
    base = [r for r in existing if not str(r.get("id", "")).startswith("IND-")]

    # Sanity: no ID collision with base signatures.
    base_ids = {r["id"] for r in base}
    for r in IND:
        if r["id"] in base_ids:
            print("COLLISION:", r["id"], file=sys.stderr)
            sys.exit(1)

    merged = base + IND
    with open(path, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2, ensure_ascii=False)
        f.write("\n")

    # Report
    from collections import Counter
    sev = Counter(r["info"]["severity"] for r in IND)
    fam = Counter(t.split(":")[1] for r in IND for t in r["info"]["tags"] if t.startswith("ind:"))
    print(f"base signatures : {len(base)}")
    print(f"indicators added: {len(IND)}  by-severity={dict(sev)}")
    print(f"by-family       : {dict(fam)}")
    print(f"total rules     : {len(merged)}")


if __name__ == "__main__":
    main()
