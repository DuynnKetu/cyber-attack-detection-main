# 📊 WAF Dashboard - User Guide

## 🎯 Overview

**Real-time monitoring dashboard** cho Hybrid WAF system với giao diện đẹp, hiện đại theo phong cách GitHub Dark Theme.

---

## 🚀 Quick Start

### Bước 1: Khởi động hệ thống

**Option A: Tự động**
```bash
start_waf.bat
```

**Option B: Thủ công**
```bash
# Terminal 1 - Backend
python web_app.py

# Terminal 2 - WAF Proxy
python waf_proxy.py
```

### Bước 2: Truy cập Dashboard

Mở browser và vào:
```
http://localhost:5000/dashboard
```

---

## 📋 Các tính năng

### 1️⃣ **Statistics Overview (4 cards)**

**📊 Total Requests**
- Tổng số requests đã xử lý
- Cập nhật real-time

**✅ Allowed Requests**
- Số requests được phép (normal traffic)
- Phần trăm so với tổng

**🚫 Blocked Requests**
- Số requests bị chặn (attacks)
- Phần trăm so với tổng

**🎯 Detection Rate**
- Tỷ lệ phát hiện attacks
- Tính theo công thức: `(blocked / total) * 100%`

---

### 2️⃣ **Live Request Log**

**Hiển thị:**
- ✅ **Allowed requests** - màu xanh
- 🚫 **Blocked requests** - màu đỏ

**Thông tin mỗi request:**
- Timestamp (giờ:phút:giây)
- HTTP Method (GET, POST, PUT, DELETE)
- URL path
- IP address
- Detector (Layer 1 hoặc Layer 2)
- Attack type (nếu bị chặn)
- Confidence score (0-100%)

**Controls:**
- **⏸️ Auto-scroll** - Tự động scroll khi có request mới
- **🗑️ Clear** - Xóa tất cả logs hiện tại

**Tính năng:**
- Tự động cập nhật mỗi 1 giây
- Giữ tối đa 50 logs gần nhất
- Animation mượt mà khi log mới xuất hiện
- Hover để highlight

---

### 3️⃣ **Attack Types Breakdown**

**Hiển thị:**
- Danh sách các loại attacks đã bị detect
- Số lượng mỗi loại
- Progress bar trực quan
- Sắp xếp theo số lượng (giảm dần)

**Các loại attacks:**
- SQL Injection
- XSS (Cross-Site Scripting)
- Path Traversal
- Command Injection
- LDAP Injection
- XXE (XML External Entity)

---

### 4️⃣ **Performance Metrics**

**Hiển thị thời gian xử lý trung bình:**

**Layer 1 (Rule-based)**
- Thời gian check regex patterns
- Thường: 1-2ms

**Layer 2 (ML)**
- Thời gian ML prediction
- Thường: 10-20ms

**Average Total**
- Thời gian xử lý trung bình tổng
- Thường: 3-5ms (vì Layer 1 filter 70-80%)

---

## 🎨 Giao diện

### Color Scheme (GitHub Dark)

**Background:**
- Primary: `#0d1117` (dark)
- Card: `#161b22` (slightly lighter)
- Border: `#30363d`

**Text:**
- Primary: `#c9d1d9` (light gray)
- Secondary: `#8b949e` (muted gray)

**Status Colors:**
- ✅ Success: `#238636` (green)
- ❌ Danger: `#da3633` (red)
- ⚠️ Warning: `#d29922` (yellow)
- 🔵 Info: `#1f6feb` (blue)
- 🌟 Accent: `#58a6ff` (bright blue)

---

## 📊 Live Demo

### Kịch bản test:

**1. Normal Requests (sẽ thấy màu xanh ✅):**
```bash
# Postman hoặc browser
GET http://localhost:5000/
GET http://localhost:5000/api/users
GET http://localhost:5000/search?q=hello
```

**2. SQL Injection Attacks (sẽ thấy màu đỏ 🚫):**
```bash
GET http://localhost:5000/search?q=' UNION SELECT * FROM users--
GET http://localhost:5000/search?q=admin' OR '1'='1
```

**3. XSS Attacks (sẽ thấy màu đỏ 🚫):**
```bash
POST http://localhost:5000/comment
Body: {"comment": "<script>alert('XSS')</script>"}
```

**4. Path Traversal (sẽ thấy màu đỏ 🚫):**
```bash
GET http://localhost:5000/file?path=../../etc/passwd
```

### Kết quả mong đợi:

Dashboard sẽ hiển thị:
```
📊 Statistics:
   Total Requests: 7
   Allowed: 3 (42.9%)
   Blocked: 4 (57.1%)
   Detection Rate: 100%

⚔️ Attack Types:
   SQL Injection: 2
   XSS: 1
   Path Traversal: 1

⚡ Performance:
   Layer 1: 1.5ms
   Layer 2: 0ms (attacks blocked by Layer 1)
   Average: 2.3ms
```

---

## 🔧 Customization

### Thay đổi refresh rate:

Mở `static/js/dashboard.js`, dòng 8-9:
```javascript
setInterval(fetchStats, 2000); // Stats: mỗi 2 giây
setInterval(fetchLogs, 1000);  // Logs: mỗi 1 giây
```

### Thay đổi số logs tối đa:

Mở `static/js/dashboard.js`, dòng 154:
```javascript
if (logs.length > 50) {  // Thay 50 thành số khác
    logs[logs.length - 1].remove();
}
```

### Thay đổi theme colors:

Mở `static/css/dashboard.css`, dòng 3-12:
```css
:root {
    --bg-dark: #0d1117;      /* Background chính */
    --bg-card: #161b22;      /* Background card */
    --text-primary: #c9d1d9; /* Text chính */
    --success: #238636;      /* Màu xanh (allowed) */
    --danger: #da3633;       /* Màu đỏ (blocked) */
    /* ... */
}
```

---

## 🐛 Troubleshooting

### Dashboard không load?

**Kiểm tra:**
1. WAF proxy đã chạy chưa: `python waf_proxy.py`
2. Port 5000 có bị chiếm không
3. Check console browser (F12) xem có lỗi gì

**Fix:**
```bash
# Restart WAF proxy
Ctrl+C  # Stop
python waf_proxy.py  # Start lại
```

### Stats không cập nhật?

**Nguyên nhân:** CORS hoặc network issue

**Fix:** Check browser console (F12) → Network tab

### Logs không hiện?

**Nguyên nhân:** Chưa có requests nào bị block

**Fix:** 
1. Gửi test attacks qua Postman
2. Check file `blocked_requests.jsonl` có data không
3. Restart WAF proxy

---

## 📱 Responsive Design

Dashboard **responsive** trên mọi thiết bị:

**Desktop (>1024px):**
- 2 cột layout (Logs | Sidebar)
- 4 stats cards trên 1 hàng

**Tablet (640px - 1024px):**
- 1 cột layout
- 2 stats cards trên 1 hàng

**Mobile (<640px):**
- 1 cột layout
- 1 stats card mỗi hàng
- Compact view

---

## 🚀 Advanced Features (Future)

### Planned enhancements:

1. **WebSocket real-time updates**
   - Thay vì polling (mỗi 1-2s), dùng WebSocket
   - Latency < 50ms

2. **Export logs to CSV/JSON**
   - Download logs để phân tích
   - Filter by date range

3. **Charts & Graphs**
   - Line chart: Requests over time
   - Pie chart: Attack types distribution
   - Area chart: Detection rate trend

4. **Alert notifications**
   - Browser notification khi có attack
   - Sound alert (configurable)

5. **Search & Filter**
   - Search logs by IP, URL, attack type
   - Date range picker
   - Advanced filters

6. **Dark/Light theme toggle**
   - Switch giữa Dark và Light mode
   - Save preference to localStorage

---

## 📚 API Endpoints

Dashboard sử dụng các endpoints sau:

### GET `/waf/stats`
Trả về statistics tổng hợp:
```json
{
  "total_requests": 100,
  "blocked": 30,
  "allowed": 70,
  "detection_rate": "30%",
  "layer_1_blocks": 25,
  "layer_2_blocks": 5,
  "rule_detections": {
    "SQL Injection": 15,
    "XSS": 10
  },
  "ml_detections": {
    "Path Traversal": 5
  },
  "processing_times": {
    "rule_avg_ms": 1.5,
    "ml_avg_ms": 12.3,
    "total_avg_ms": 3.2
  }
}
```

### GET `/waf/logs`
Trả về 100 logs gần nhất:
```json
{
  "logs": [
    {
      "timestamp": "2024-11-07T14:30:45.123",
      "detector": "Rule-based (Layer 1)",
      "attack_type": "SQL Injection",
      "confidence": 1.0,
      "method": "GET",
      "url": "/search?q=' UNION SELECT *",
      "content": "",
      "ip": "127.0.0.1"
    }
  ],
  "count": 100
}
```

### GET `/waf/health`
Health check:
```json
{
  "status": "healthy",
  "rule_detector": "enabled",
  "ml_detector": "enabled",
  "timestamp": "2024-11-07T14:30:45.123"
}
```

---

## 🎓 Tips & Tricks

1. **Giữ Dashboard mở** khi test với Postman để xem real-time results

2. **Sử dụng auto-scroll** để theo dõi logs mới nhất

3. **Clear logs thường xuyên** để dễ theo dõi

4. **Check Performance metrics** để đảm bảo WAF không làm chậm hệ thống

5. **Monitor Attack Types** để biết loại attacks phổ biến nhất

---

## 📄 Files Structure

```
smart_fireWall_with_ML/
├── templates/
│   └── dashboard.html          # Dashboard HTML template
├── static/
│   ├── css/
│   │   └── dashboard.css       # Dashboard styles
│   └── js/
│       └── dashboard.js        # Dashboard JavaScript
├── waf_proxy.py                # WAF proxy với dashboard routes
└── DASHBOARD_GUIDE.md          # File này
```

---

**Enjoy your beautiful WAF Dashboard! 🎉**

Nếu có vấn đề gì, check logs hoặc tham khảo `DEPLOYMENT_GUIDE.md`.
