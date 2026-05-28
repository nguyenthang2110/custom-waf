# WAF Rule Documentation

Tài liệu hệ thống rule của WAF (schema v2).

## Đọc file nào trước?

| Bạn là... | Đọc... |
|---|---|
| Người mới, muốn **viết một rule** | [RULE_GUIDE.md](./RULE_GUIDE.md) — hướng dẫn từng bước |
| Cần tra cứu **một field cụ thể** | [RULE_REFERENCE.md](./RULE_REFERENCE.md) — reference đầy đủ |
| Muốn biết **vì sao thiết kế như vậy** | [DESIGN_NOTES.md](./DESIGN_NOTES.md) — lý do từng quyết định |
| Có rule **schema v1** muốn nâng cấp | [MIGRATION.md](./MIGRATION.md) — bảng chuyển đổi v1 → v2 |
| Muốn xem **ví dụ thực tế** | [examples/](./examples/) — 6 rule mẫu phổ biến |

## Schema v2 trong 30 giây

Một rule là một file JSON có 7 phần:

```jsonc
{
  "id":      "...",       // 1. Định danh
  "info":    { ... },     // 2. Metadata (category, severity, tags)
  "when":    { ... },     // 3. Khi nào áp dụng rule (method, path, score range)
  "inspect": [ ... ],     // 4. Lấy data từ đâu (path, query, body, header...)
  "transforms": [ ... ],  // 5. Chuẩn hoá data (url_decode, lowercase...)
  "detect":  { ... },     // 6. So với pattern nào (regex, contains, wordlist...)
  "action":  { ... },     // 7. Khi match thì làm gì (score, label, log, block, ML confirm, track)
  "except":  { ... }      //    Trường hợp bỏ qua (whitelist)
}
```

Đọc tiếp [RULE_GUIDE.md](./RULE_GUIDE.md) để xem giải thích từng phần kèm ví dụ.

## So với schema v1

Schema v2 fix 3 vấn đề lớn của v1 và bổ sung 4 tính năng:

| Vấn đề v1 | v2 giải quyết |
|---|---|
| Pattern không có `negate` (không express "không chứa X") | ✓ `pattern.negate` |
| Nhiều pattern luôn là OR ngầm, không thể AND | ✓ `detect.logic: "any" \| "all"` |
| `action` mâu thuẫn với `scoring`, một số rule có một số rule không | ✓ Gộp vào `action` duy nhất, có `block`/`log`/`labels`/... |

| Tính năng mới | Mục đích |
|---|---|
| `action.ml_confirm` | Gọi ML service để xác nhận signature match, giảm false positive |
| `action.track` | Đếm số lần match theo IP/session (chống brute-force, scanner) |
| `action.labels` + `when.require_labels` | Một rule tag request, rule sau đọc tag để quyết định |
| `when.min_score` / `max_score` | Rule "amplifier" chỉ chạy khi score đã ở vùng nghi ngờ |

Chi tiết: [DESIGN_NOTES.md](./DESIGN_NOTES.md).
