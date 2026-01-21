# Giải Thích: Tại Sao Socket.io Bị Block?

## Nguyên Nhân

Từ hình ảnh và audit logs, Socket.io requests bị **TEMPORARILY_BLOCKED** mặc dù:
- `total_score = 0.0` (không match rule nào)
- `matched_rules = 0` (không có rule trigger)

### Root Cause: Behavior Detection - IP Temporarily Blocked

**IP của bạn (`[::1]` - localhost IPv6) bị block tạm thời vì:**

1. **Testing gây ra nhiều blocked requests**
   - Trong quá trình test, bạn đã gửi 28 attack payloads
   - Tất cả đều bị WAF block → `failed_attempts` tăng cao

2. **Brute Force Detection Triggered**
   - Code trong `detector.go` line 233:
   ```go
   if stats.failedAttempts >= d.config.BruteForceThreshold {
       // Block IP temporarily
       stats.isBlocked = true
       stats.blockedUntil = now.Add(10 * time.Minute)
   }
   ```
   - Default threshold: **5 failed attempts trong 5 phút**
   - Bạn đã có **28 blocked requests** → Vượt ngưỡng nhiều

3. **Temporary Block Applied**
   - Line 181-185 trong `detector.go`:
   ```go
   if stats.isBlocked && now.Before(stats.blockedUntil) {
       result.ThreatTypes = append(result.ThreatTypes, "TEMPORARILY_BLOCKED")
       result.RecommendAction = "BLOCK"
       return result
   }
   ```
   - Tất cả requests từ IP này bị block **10 phút** kể từ lần trigger

4. **Socket.io là Legitimate Traffic nhưng vẫn bị chặn**
   - Socket.io không phải attack
   - Nhưng IP đã bị đánh dấu "nguy hiểm" → Block tất cả

---

## Chi Tiết Audit Log

### Before Block (11:09:52)
```json
{
  "timestamp": "2026-01-16T11:09:52.25478+07:00",
  "path": "/socket.io/",
  "decision": "ALLOW",
  "total_score": 0,
  "behavior_threats": [
    "REPEATED_SQL Injection",
    "REPEATED_Cross-Site Scripting",
    "REPEATED_Path Traversal",
    ...
  ]
}
```
- Decision: `ALLOW` (chưa chặn)
- Nhưng đã detect: `REPEATED_*` attacks

### After Block (11:09:17 - 11:09:47)
```json
{
  "timestamp": "2026-01-16T11:09:17.132361+07:00",
  "path": "/socket.io/",
  "decision": "BLOCK",
  "total_score": 0,
  "rule_score": 0,
  "behavior_threats": ["TEMPORARILY_BLOCKED"],
  "block_reason": "Overridden by behavior detection: TEMPORARILY_BLOCKED"
}
```
- Decision: `BLOCK`
- Reason: Behavior detection, **KHÔNG PHẢI rules**
- IP sẽ bị block đến khi `blockedUntil` timeout

---

## Giải Pháp

### Option 1: Whitelist Localhost (Khuyên Dùng cho Development)

**Thêm localhost vào whitelist để bypass behavior detection:**

```bash
# Thêm IP vào whitelist
curl -X POST http://localhost:8080/api/admin/whitelist \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "::1",
    "reason": "Development - Localhost IPv6",
    "duration": 86400
  }'

# Hoặc IPv4
curl -X POST http://localhost:8080/api/admin/whitelist \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "127.0.0.1",
    "reason": "Development - Localhost IPv4",
    "duration": 86400
  }'
```

**Duration**: 86400 seconds = 24 hours

---

### Option 2: Manual Unblock IP

**Unblock ngay lập tức:**

```bash
# Unblock specific IP
curl -X POST http://localhost:8080/api/admin/unblock \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "::1"
  }'
```

**Hoặc dùng Go code trực tiếp:**

```go
// Trong code WAF
detector.UnblockIP("[::1]")
```

---

### Option 3: Tăng Brute Force Threshold (Development Mode)

**Config file `configs/config.yaml`:**

Tìm hoặc thêm section:
```yaml
behavior:
  brute_force_threshold: 100    # Tăng từ 5 → 100 (cho testing)
  brute_force_window: 5m
  scanning_enabled: false       # Tắt scanning detection
  bot_detection_enabled: false  # Tắt bot detection (optional)
```

**Restart WAF** sau khi sửa config.

---

### Option 4: Disable Behavior Detection (Chỉ cho Dev)

**Tạm thời tắt hoàn toàn behavior detection:**

Trong code khởi tạo WAF, set:
```go
behaviorConfig := behavior.BehaviorConfig{
    BruteForceThreshold: 999999,  // Rất cao
    BotDetectionEnabled: false,
    ScanningEnabled:     false,
    VelocityEnabled:     false,
}
```

**⚠️ Cảnh báo**: Chỉ dùng trong development!

---

### Option 5: Đợi Timeout (10 phút)

IP sẽ tự động unblock sau **10 phút** kể từ lần block cuối.

Check thời gian còn lại:
```bash
# Get IP stats
curl http://localhost:8080/api/metrics/ip/::1 | jq .
```

Output:
```json
{
  "client_ip": "::1",
  "is_blocked": true,
  "blocked_until": "2026-01-16T11:19:17+07:00",
  "failed_attempts": 28
}
```

---

## Recommended Solution

**Cho development environment:**

1. **Whitelist localhost** (Option 1)
   ```bash
   # Add to whitelist permanently for dev
   echo '[::1]' >> configs/whitelist.txt
   echo '127.0.0.1' >> configs/whitelist.txt
   ```

2. **Tăng threshold** trong config (Option 3)
   ```yaml
   behavior:
     brute_force_threshold: 50
   ```

3. **Restart WAF**
   ```bash
   pkill -f "bin/waf"
   make run
   ```

**Cho production:**

- Giữ nguyên default config (threshold=5)
- Chỉ whitelist IPs cần thiết (VPN, office IPs)
- **KHÔNG** whitelist public IPs

---

## Prevention

**Để tránh bị block khi testing trong tương lai:**

### 1. Test với Whitelist
```bash
# Luôn whitelist testing IP trước khi test
curl -X POST http://localhost:8080/api/admin/whitelist \
  -d '{"ip":"::1", "duration":3600}'
```

### 2. Test Incrementally
```bash
# Thay vì run all tests cùng lúc
python3 test.py --limit 5  # Test từng ít payloads
sleep 60                    # Đợi giữa các batch
python3 test.py --limit 5
```

### 3. Reset Stats Between Tests
```bash
# Clear IP stats trước mỗi test run
curl -X POST http://localhost:8080/api/admin/reset-stats \
  -d '{"ip":"::1"}'
```

### 4. Use Test Mode Config
```yaml
# configs/config.test.yaml
behavior:
  brute_force_threshold: 1000
  bot_detection_enabled: false
```

Run with:
```bash
./bin/waf -config configs/config.test.yaml
```

---

## Understanding Behavior Detection

### How It Works

```
Request → WAF Rules → Score Calculation → Behavior Analysis
                                                    ↓
                                         Track per-IP stats:
                                         - Failed attempts
                                         - Request velocity
                                         - Attack patterns
                                                    ↓
                                         If threshold exceeded:
                                         - Set isBlocked = true
                                         - blockedUntil = now + 10min
                                                    ↓
                                         All future requests BLOCKED
                                         (even legitimate ones!)
```

### Why It's Good (Production)

✅ **Protects against**:
- Brute force attacks
- Port scanning
- Automated vulnerability scanners
- DDoS from single IPs

### Why It's Annoying (Development)

❌ **Blocks legitimate testing**:
- Your own penetration testing
- Automated test suites
- Development traffic

**Solution**: Separate configs for dev vs prod!

---

## Quick Fix Commands

```bash
# 1. Unblock your IP NOW
curl -X POST http://localhost:8080/api/admin/unblock -d '{"ip":"::1"}'

# 2. Add to permanent whitelist
curl -X POST http://localhost:8080/api/admin/whitelist \
  -d '{"ip":"::1", "duration":86400, "reason":"Dev localhost"}'

# 3. Check if unblocked
curl http://localhost:8080/socket.io/
# Should return 200 instead of 403
```

---

## Summary

| Câu hỏi | Trả lời |
|---------|---------|
| **Tại sao block?** | IP bị temporary block do quá nhiều attack attempts (28 requests) |
| **Rule nào trigger?** | KHÔNG có rule - Behavior detection (brute force) |
| **Score bao nhiêu?** | 0.0 (không phải rule-based block) |
| **Block bao lâu?** | 10 phút từ lần cuối trigger |
| **Fix thế nào?** | Whitelist localhost hoặc tăng threshold |
| **Tại sao Socket.io?** | IP blocked → TẤT CẢ requests đều block (kể cả legitimate) |

---

**Kết luận**: Đây là **tính năng bảo mật** (anti-brute force), không phải bug. Trong production thì tốt, nhưng development cần config riêng.
