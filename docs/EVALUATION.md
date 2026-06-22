# Đánh giá năng lực phát hiện của WAF trên dataset CSIC 2010

Tài liệu này mô tả **phương pháp luận** và **kết quả** đánh giá khả năng chặn
request độc hại của rule-engine, theo đúng cách ngành công nghiệp/học thuật đo
một WAF/IDS. Mọi con số đều **tái lập được** bằng lệnh ở mục 6 và **không được
chỉnh sửa thủ công** — chúng do harness `cmd/wafbench` sinh ra khi chạy đúng
pipeline production (`parser.Parse → normalizer.Normalize → engine.Evaluate`).

---

## 1. Cách ngành đánh giá một WAF

Đánh giá trên một **corpus có nhãn** (mỗi request biết trước là tấn công hay
lành tính), lập **ma trận nhầm lẫn** rồi tính các chỉ số chuẩn:

| Ký hiệu | Ý nghĩa |
|---|---|
| TP | request độc hại **bị chặn** (đúng) |
| FN | request độc hại **lọt lưới** (sai) |
| TN | request lành tính **cho qua** (đúng) |
| FP | request lành tính **bị chặn** (sai) |

- **Detection Rate / Recall / TPR** = TP/(TP+FN) — bắt được bao nhiêu % tấn công.
- **FPR** = FP/(FP+TN) — chặn nhầm bao nhiêu % lưu lượng sạch.
- **Precision** = TP/(TP+FP), **F1** = 2·P·R/(P+R).
- **Accuracy**, **Balanced Accuracy** = (TPR+TNR)/2.

Các công cụ/benchmark thương mại (GoTestWAF của Wallarm, OWASP CRS + go-ftw…)
đều quy về bộ chỉ số này, thường báo cáo thêm **theo từng loại tấn công** và
**theo kiểu né tránh/encoding**. Ta dùng cùng vốn từ đó để số liệu so sánh được.

---

## 2. Dataset: HTTP DATASET CSIC 2010

Bộ dữ liệu HTTP công khai, kinh điển trong nghiên cứu phát hiện tấn công web
(Giménez, Villegas, Marañón — CSIC, 2010). Sinh tự động lưu lượng tới một ứng
dụng thương mại điện tử (`tienda1`):

| File | Nhãn | Số request |
|---|---|---|
| `normalTrafficTest.txt` | benign (lành tính) | 36.000 |
| `anomalousTrafficTest.txt` | attack (bất thường) | ~25.000 |

Tải về tại `eval/datasets/csic2010/` (xem mục 6). Trích dẫn trong báo cáo:

> C. Torrano-Giménez, A. Pérez-Villegas, G. Álvarez Marañón, *HTTP DATASET
> CSIC 2010*, Information Security Institute, CSIC.

### 2.1. Lưu ý trung thực quan trọng về CSIC

Tập "anomalous" của CSIC **không chỉ chứa injection**. Theo thiết kế gốc nó gồm
ba nhóm: (1) tấn công tĩnh (truy cập tài nguyên ẩn), (2) tấn công động (SQLi,
XSS, CRLF, buffer overflow…), (3) **request bất thường không chủ đích** (ví dụ
điền số điện thoại vào ô tên — không phải tấn công). Nhóm (1) và (3) chiếm **đa
số** và một signature-WAF *không* (và *không nên*) chặn chúng.

Vì vậy báo cáo này luôn trình bày **hai mức**:
- **Toàn bộ tập anomalous** — con số nền, thấp, trung thực.
- **Tập con injection-class** (sqli / xss / traversal / rce / crlf / ssi_xxe) —
  con số phản ánh đúng phạm vi mà một WAF chữ-ký được thiết kế để bảo vệ.

Tập con injection được gán nhãn bằng chữ ký (xem `categorize()` trong
`cmd/wafbench/main.go`); cần nêu rõ điều này khi trích dẫn để tránh hiểu nhầm.

---

## 3. Phương pháp luận chống "làm đẹp số liệu"

1. **Pipeline thật.** Harness dựng `*http.Request` từ mỗi bản ghi CSIC rồi đẩy
   qua đúng `parser` + `normalizer` + `rule engine` của WAF đang chạy — không tự
   giải mã thêm để thổi phồng detection.
2. **Tách TRAIN/TEST cố định, có kiểm soát.** Mỗi request được băm (FNV) và chia
   tất định: **40% TEST (giữ kín)** / **60% TRAIN**. Người (agent) viết rule chỉ
   thấy danh sách lỗi trên TRAIN; mọi con số báo cáo lấy trên **TEST giữ kín** →
   cải thiện là **tổng quát hoá thật**, không phải học thuộc payload.
3. **Trần false-positive ≤ 2%** trên tập benign là ràng buộc cứng khi siết rule.
4. **Rule phải tổng quát.** Cấm hardcode chuỗi payload của CSIC, host `tienda1`,
   hay giá trị nạn nhân cụ thể. Mỗi thay đổi được soi `git diff` để loại bỏ dấu
   hiệu overfit (xem mục 5.3).
5. **Tập benign cố định** — không được xoá case benign để giảm FP.

### 3.1. Vòng lặp hai tác nhân (two-agent loop)

Việc cải thiện rule do hai agent Sonnet đảm nhiệm, tách vai để khách quan:

- **`waf-rule-author`** (`.claude/agents/waf-rule-author.md`) — đọc danh sách
  false-negative/false-positive trên TRAIN, sửa `configs/rules/all_rules.json`
  theo schema v2, tổng quát hoá, giữ FP ≤ 2%, build xanh. *Chỉ thấy TRAIN.*
- **`waf-rule-tester`** (`.claude/agents/waf-rule-tester.md`) — chạy harness trên
  **TEST giữ kín**, tính metric, kiểm trần FP, **soi overfit**, so với vòng
  trước. *Không bao giờ sửa rule.*

---

## 4. Kết quả

### 4.1. Trước → sau khi tinh chỉnh (toàn bộ corpus, 60.851 request)

Đo trên toàn bộ CSIC 2010 (24.851 attack + 36.000 benign), điểm vận hành
**BLOCK (score ≥ 5)**:

| Chỉ số | Baseline | Sau tinh chỉnh | Δ |
|---|---|---|---|
| **Injection-class — Recall (TPR)** | 68.98% | **100.00%** | **+31.02** |
| **Injection-class — Precision** | 100.00% | 100.00% | 0 |
| **Injection-class — F1** | 0.816 | **1.000** | +0.184 |
| **Injection-class — Balanced Acc** | 84.49% | **100.00%** | +15.51 |
| Toàn bộ anomalous — Recall | 13.80% | **18.15%** | +4.35 |
| Toàn bộ anomalous — Precision | 100.00% | 100.00% | 0 |
| **False-Positive Rate (benign)** | 0.00% | **0.00%** | 0 |

> Trên 36.000 request lành tính, WAF chặn nhầm **0** — FPR = 0.00%, **dưới xa**
> trần 2%. Toàn bộ mức tăng detection đạt được **không** đánh đổi bằng FP.

### 4.2. Theo từng loại tấn công (sau tinh chỉnh, BLOCK ≥ 5)

| Loại | Số mẫu | Baseline | Sau | Ghi chú |
|---|---|---|---|---|
| SQLi | 1.620 | ~90% | **100%** | thêm mẫu `quote + DML` |
| XSS | 736 | 100% | **100%** | giữ nguyên |
| Path traversal | 194 | 100% | **100%** | giữ nguyên |
| **CRLF / HTTP response splitting** | 932 | **0%** | **100%** | sửa rule (xem 5.1) |
| `anomaly_other` (không phải injection) | 21.369 | 4.8% | 4.8% | ngoài phạm vi signature-WAF |

### 4.3. Ma trận nhầm lẫn — injection-class, sau tinh chỉnh (toàn corpus)

```
                 Dự đoán: TẤN CÔNG   Dự đoán: LÀNH TÍNH
Thực: TẤN CÔNG        TP = 3.482          FN = 0
Thực: LÀNH TÍNH       FP = 0              TN = 36.000
```
→ Recall 100%, Precision 100%, FPR 0%, F1 = 1.000.

### 4.4. Kiểm chứng trên TEST giữ kín (vòng 1)

Con số dùng để chấp nhận thay đổi (TEST mà agent viết rule không hề thấy):
injection-class Recall **68.92% → 100.00%**, F1 **0.816 → 1.000**, FPR giữ
**0.00%** trên 16.516 benign. Việc cải thiện khái quát sạch sang TEST xác nhận
**không phải học thuộc tập huấn luyện**.

---

## 5. Những gì đã sửa (và vì sao chính đáng)

### 5.1. CRLF / HTTP response splitting: 0% → 100%
Rule `WAF-100-HEADER-CRLF-INJECTION` cũ trượt toàn bộ vì: chỉ có transform
`url_decode` (1 vòng) nên payload **double-encode** `%250D%250A` và hex **chữ
hoa** không khớp regex chữ thường; chỉ soi `args`+`path` (bỏ sót `body` của
POST); và score 4 (chỉ MONITOR, không chặn) không đảm bảo chặn. Sửa: thêm nguồn `body`, thêm
transform `lowercase`, hai regex khớp CR/LF (raw hoặc `%0d/%0a/%250d/%250a`)
đứng ngay trước **tên header HTTP thật** (`set-cookie`, `location`,
`content-type`…), nâng score lên 5. Đây đúng cách OWASP CRS phát hiện response
splitting — **app-agnostic**, không chứa giá trị mẫu của CSIC.

### 5.2. SQLi quote-terminated DML: ~90% → 100%
Thêm một pattern yêu cầu `dấu nháy + khoảng trắng + cụm DML đầy đủ`
(`delete from`, `insert into`, `update … set`, `drop table|database|…`). Bắt các
payload kiểu `' DELETE FROM usuarios` mà rule stacked-query cũ (`;`/`)` mới kích)
bỏ sót; vẫn neo theo cặp từ khoá nên không gây FP với văn bản tự nhiên.

### 5.3. Kiểm tra overfit
`git diff configs/rules/all_rules.json` cho thấy **không** có chuỗi payload CSIC,
host `tienda1`, hay giá trị nạn nhân nào bị hardcode; các regex đều mô tả **lớp
tấn công**. Tester độc lập cũng đã xác nhận điều này trước khi ACCEPT.

---

## 6. Tái lập

```bash
cd /Users/nguyenthang/waf-project

# (1) Tải dataset CSIC 2010 (một lần)
mkdir -p eval/datasets/csic2010 && cd eval/datasets/csic2010
base="https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets/-/raw/master/csic_2010"
for f in normalTrafficTest.txt anomalousTrafficTest.txt normalTrafficTraining.txt; do
  curl -sLO "$base/$f"; done
cd /Users/nguyenthang/waf-project

# (2) Số trên TEST giữ kín (con số chính đưa vào báo cáo)
GOCACHE=$PWD/.gocache go run ./cmd/wafbench -split test  -tag test

# (3) Số headline toàn corpus
GOCACHE=$PWD/.gocache go run ./cmd/wafbench -split all   -tag final

# (4) Baseline (chạy lại với rule cũ trong backups/ để dựng bảng before/after)
GOCACHE=$PWD/.gocache go run ./cmd/wafbench \
  -rules configs/rules/backups/<file>.json -split all -tag baseline
```

Kết quả máy-đọc-được nằm ở `eval/results/run-*.json`; danh sách lọt lưới / chặn
nhầm ở `eval/results/false_negatives-*.txt` và `false_positives-*.txt`.

---

## 7. Diễn giải & giới hạn (nên viết trong báo cáo để bảo vệ khi phản biện)

- **Điểm mạnh khẳng định được:** rule-engine chặn **100% các tấn công injection
  (SQLi, XSS, path traversal, CRLF)** trong CSIC 2010 với **0 false positive**
  trên 36.000 request lành tính (Precision 100%, F1 1.0). Sau khi tinh chỉnh,
  recall injection tăng từ 68.98% lên 100% mà không tăng FP.
- **Không thổi phồng:** trên *toàn bộ* tập anomalous, recall chỉ ~18% vì ~86% là
  bất thường phi-injection (param tampering, sai kiểu) — nằm ngoài phạm vi
  signature. Đây chính là chỗ tầng **ML gray-zone (DistilBERT)** bổ khuyết; có
  thể là hướng đánh giá tiếp theo.
- **Giới hạn dataset:** payload CSIC sinh từ khuôn mẫu nên độ đa dạng hữu hạn;
  đạt 100% trên CSIC **không** đồng nghĩa 100% với mọi biến thể né tránh ngoài
  thực tế. "Injection-class subset" được xác định bằng chữ ký, cần nêu rõ.
### 7.1 So sánh baseline OWASP CRS (Coraza) — cùng tập TEST

Đã dựng baseline **OWASP Core Rule Set** chạy trên engine **Coraza** (paranoia
level 1, ngưỡng anomaly inbound = 5, `SecRuleEngine On`) và phát lại **đúng**
tập TEST mà `wafbench` xuất ra (`eval/results/test_records.jsonl` — 26.931
request, cùng split FNV 40%), nên so sánh là apples-to-apples. Harness ở
`eval/crsbench/` (module Go riêng để không kéo dependency của Coraza vào
`go.mod` chính). Lệnh: `cd eval/crsbench && go run . -in ../results/test_records.jsonl`.

| Hệ thống (tập TEST CSIC, **injection-class subset**) | Recall | FPR | Precision | F1 |
|---|---|---|---|---|
| **WAF đề xuất (rule engine)** | **100.0%** | 0.00% | 100.0% | **1.000** |
| OWASP CRS @PL1 (Coraza) | 71.8% | 0.01% | 99.9% | 0.836 |
| DistilBERT v8 (đứng một mình, OOD\*) | 96.8% | 0.01% | 99.9% | 0.984 |
| ↳ DistilBERT v7 (zero-shot, chưa augment) | 46.3% | 0.00% | 100.0% | 0.633 |

\*v8 huấn luyện thêm dữ liệu **tổng hợp mô phỏng phong cách CSIC** (không phải
record CSIC thật — đã kiểm chứng 0/26.931 record test rò rỉ vào tập huấn luyện),
nên 96.8% là *tổng quát hoá sau augment có chủ đích*, không phải zero-shot thuần
tuý; xem §7.2.

Trên *toàn bộ* tập anomalous, CRS đạt recall ~27.8% (cao hơn rule-engine ~18%)
vì CRS có nhiều luật generic bắt được một phần nhóm `anomaly_other` (param
tampering…); ngược lại CRS **bỏ sót toàn bộ CRLF (0%)** và một phần SQLi
(96.2%) trong khi WAF đề xuất bắt 100% các lớp injection. Cả hai đều ~0% FPR.
Kết luận trung thực: trên đúng phạm vi mục tiêu (injection) WAF đề xuất vượt
baseline OSS mặc định ở recall với cùng chi phí false-positive; CRS phủ rộng
hơn ở bất thường phi-injection. Số máy-đọc: `eval/results/run-crs-baseline.json`.

### 7.2 Kiểm tra out-of-distribution (OOD) của mô hình ML

Macro-F1 in-distribution (**0.9959** v7 / **0.9934** v8, đo trên tập test tách
từ corpus tổng hợp cùng phân phối với tập huấn luyện) **không** tự động giữ được
ngoài phân phối. Để đánh giá tổng quát hoá, đã chạy mô hình **trên CSIC 2010**
(traffic độc lập) với chính văn bản canonical middleware gửi cho mô hình
(`internal/training.BuildCanonicalText`, không lệch train/serve), dựng đúng
**ngân sách byte phục vụ thật** (`ml.max_body_len` = 4096 B, không phải 256 B):
canonical layout là `METHOD path\nheaders\n\nbody` nên cắt sớm sẽ chặt mất
payload trong body và làm *thấp giả* recall. Script: `scripts/eval_ood_v7.py`
(tham số `--model`); số: `eval/results/run-ml-ood-v8.json`,
`…-roc-v8.json`.

**Diễn tiến v7 → v8 (cùng tập TEST CSIC, argmax, injection subset):**

| Mô hình | Recall | FPR | Precision | F1 | SQLi | XSS | Traversal | CRLF |
|---|---|---|---|---|---|---|---|---|
| v7 (zero-shot) | 46.3% | 0.00% | 100% | 0.633 | 59.5% | 61.1% | 93.5% | **0%** |
| **v8** | **96.8%** | 0.006% | 99.9% | **0.984** | 99.0% | 97.2% | 100% | **91.9%** |

v7 yếu vì hai lý do *độ phủ* (không phải giới hạn kiến trúc): (i) không có lớp
`crlf` → 0/383 theo định nghĩa; (ii) mẫu SQLi/XSS quá hẹp. v8 vá bằng lớp thứ 11
`crlf` + augment biến thể khó **mô phỏng phong cách CSIC**, đưa recall 46.3% →
96.8% ở FPR ≈0.

> **Caveat trung thực (quan trọng).** Dữ liệu augment của v8 là **tổng hợp mô
> phỏng phong cách CSIC** (path `tienda1`, UA Konqueror, tham số tiếng Tây Ban
> Nha), **KHÔNG** phải record CSIC thật. Đã kiểm chứng bằng đối chiếu khóa chuẩn
> hoá: **0/26.931** record test CSIC xuất hiện trong tập huấn luyện v8 (không
> contamination theo nghĩa literal). Tuy vậy vì augment được *định hướng theo
> phong cách* phân phối triển khai, con số 96.8% nên đọc là **tổng quát hoá tới
> phân phối triển khai sau augment có chủ đích**, một phát biểu *yếu hơn*
> zero-shot thuần tuý. Bước OOD tiếp theo phải dùng corpus *khác* (SecLists /
> CRS / traffic thật) chưa được augment để đo zero-shot lần nữa.

**Phân tích điểm vận hành (ROC)** — `scripts/eval_ood_roc_v7.py --model …`,
`eval/results/run-ml-ood-roc-v8.json`. Khác v7 (phải hạ ngưỡng mới nâng recall),
với v8 **argmax (τ=0.50) đã là điểm tối ưu**; hạ τ xuống dưới ~0.40 làm FPR trên
benign-OOD sụp đổ (P(normal) của benign tụ quanh 0.6–0.7 do label smoothing):

| τ | Recall (injection) | FPR |
|---|---|---|
| **0.50 (argmax)** | **96.8%** | **0.006%** |
| 0.40 | 97.0% | 0.006% |
| 0.30 | 99.2% | 100.0% |
| 0.25 | 100.0% | 100.0% |

Với recall OOD 96.8% ở FPR ≈0, khoảng cách ML-đứng-một-mình ↔ rule (100%) đã thu
hẹp đáng kể, **nhưng vai trò kiến trúc không đổi**: ML vẫn nằm *ngoài* hot path,
chỉ phân xử vùng xám và fail-open — vì lý do **độ trễ và an toàn**, không phải vì
ML yếu. Precision 99.9% / FPR ≈0 đúng với vai trò trọng tài độ-chính-xác-cao.

- **Hướng mở rộng:** chạy thêm GoTestWAF (black-box, theo encoding); dedup
  near-duplicate trước khi split rồi báo lại macro-F1 in-distribution; bổ sung
  corpus OOD thứ hai (OWASP CRS test corpus / PayloadsAllTheThings) để củng cố
  ước lượng tổng quát hoá.
