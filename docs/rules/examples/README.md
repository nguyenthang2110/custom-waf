# Example Rules

6 rule mẫu minh hoạ schema v2. Đọc kèm với [RULE_GUIDE.md](../RULE_GUIDE.md).

| File | Mô tả | Tính năng minh hoạ |
|---|---|---|
| [01-sqli-basic.json](./01-sqli-basic.json) | SQLi UNION + Boolean | Schema cơ bản, signature + `ml_confirm` |
| [02-xss.json](./02-xss.json) | XSS các biến thể | Multi-pattern OR, transform `html_decode`, `except.path_prefixes` |
| [03-cve-log4shell.json](./03-cve-log4shell.json) | CVE-2021-44228 virtual patch | `action.block: true`, multi-source `inspect` (headers + body + cookies), score cao |
| [04-scanner-bot.json](./04-scanner-bot.json) | Scanner UA + bot heuristic | `wordlist`, `track` (counter theo IP), `exclude_labels` |
| [05-ato-bruteforce.json](./05-ato-bruteforce.json) | Brute force /login | `track` (scope `ip` và `session`), `on_threshold_labels` |
| [06-ml-grayzone.json](./06-ml-grayzone.json) | ML gray-zone + signature confirmation | `when.min_score`/`max_score`, `require_labels`, `ml_confirm` standalone |

## Cách đọc

1. **Đọc [01-sqli-basic.json](./01-sqli-basic.json) trước** — rule "bình thường" nhất.
2. **02 và 03** — biến thể về match logic + force block.
3. **04 và 05** — stateful tracking (counter cross-request).
4. **06** — ML integration patterns.

## Map tính năng → ví dụ

| Tính năng cần xem | Ví dụ |
|---|---|
| `info` tags + references | 03 |
| `when.methods` + `path_exclude` | 01 |
| `when.path_prefix` | 05 |
| `when.min_score` / `max_score` | 06 |
| `when.require_labels` | 06 |
| `when.exclude_labels` | 04 (bot rule) |
| `inspect.source: args` | 01, 02 |
| `inspect.source: headers_all` | 03 |
| `inspect.source: header name=...` | 02, 03 |
| `inspect.source: user_agent` | 04 |
| `transforms` chain phổ biến | 01 (SQLi), 02 (XSS), 03 (CVE) |
| `detect.logic: any` | 01, 02 |
| `pattern.type: regex` | 01, 02, 03 |
| `pattern.type: wordlist` | 04 |
| `pattern.type: contains` | 02, 05 |
| `pattern.type: starts_with` | 05 |
| `pattern.type: equals` | 04 (bot) |
| `pattern.type: length_gt` | 06 |
| `action.score` + `labels` | tất cả |
| `action.block: true` | 03 |
| `action.ml_confirm` | 01 (Boolean SQLi), 02 (event handler), 06 |
| `action.track` (scope: ip) | 04, 05 |
| `action.track` (scope: session) | 05 |
| `except.paths` | 01 |
| `except.path_prefixes` | 04 |

## Tải vào WAF

Sao chép file mẫu vào `configs/rules/`:

```bash
cp docs/rules/examples/*.json configs/rules/
```

Rồi reload qua dashboard hoặc API:

```bash
curl -X POST http://localhost:8080/waf-api/rules/upload \
     -H "Authorization: Bearer <admin-token>" \
     -F "file=@configs/rules/01-sqli-basic.json"
```

(Hoặc chỉ cần restart WAF nếu file load lúc startup.)
