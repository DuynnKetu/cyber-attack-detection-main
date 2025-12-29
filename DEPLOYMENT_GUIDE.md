# 🛡️ Hybrid WAF System - Deployment Guide

## 🎯 Tổng quan hệ thống

Hệ thống **Hybrid WAF** sử dụng kiến trúc 2 lớp phòng thủ:

```
┌─────────────────────────────────────────┐
│     HTTP Request từ Client              │
└──────────────┬──────────────────────────┘
               ↓
   ┌───────────────────────────────┐
   │ 🛡️ LAYER 1: Rule-based       │
   │ - Fast (1-2ms)                │
   │ - Catches 70-80% attacks      │
   └──────────┬────────────────────┘
              ↓
        ┌─────────┐
        │ BLOCK?  │
        └────┬────┘
     Yes ←───┴───→ No
      ↓              ↓
  Return 403   ┌────────────────────┐
               │ 🤖 LAYER 2: ML     │
               │ - Deep (10-20ms)   │
               │ - Catches subtle   │
               └─────┬──────────────┘
                     ↓
               ┌─────────┐
               │ BLOCK?  │
               └────┬────┘
            Yes ←───┴───→ No
             ↓              ↓
         Return 403   Forward to Backend
```

## 📊 Expected Performance

- **Layer 1 (Rule-based)**: Blocks 70-80% obvious attacks, ~0.01% FP
- **Layer 2 (ML)**: Blocks 76.6% of remaining attacks (threshold 0.7), ~0.03% FP
- **Combined**: ~94-95% total detection, <0.04% FP rate
- **Processing time**: 
  - Normal requests: 1-2ms (rule only)
  - Suspicious requests: 11-22ms (rule + ML)

## 🔧 Installation

### 1. Install Dependencies

```bash
pip install flask requests joblib scikit-learn scipy xgboost lightgbm imbalanced-learn colorama
```

### 2. Verify Model File

Đảm bảo file model đã có:
```
waf_plots/
└── models/
    └── firewall_model_bundle.joblib
```

### 3. Project Structure

```
smart_fireWall_with_ML/
├── rule_detector.py          # Layer 1: Rule-based detection
├── ml_detector.py            # Layer 2: ML detection
├── waf_proxy.py              # Main WAF proxy server
├── web_app.py                # Sample web application (backend)
├── attack_sim.py             # Attack simulator for testing
├── waf_plots/
│   └── models/
│       └── firewall_model_bundle.joblib
├── waf_proxy.log             # WAF logs (auto-generated)
└── blocked_requests.jsonl    # Blocked requests log (auto-generated)
```

## 🚀 Quick Start

### Step 1: Start Backend Web Application

```bash
python web_app.py
```

Output:
```
🌐 SAMPLE WEB APPLICATION STARTED
🚀 Application running on: http://localhost:5001
```

### Step 2: Start WAF Proxy (in new terminal)

```bash
python waf_proxy.py
```

Output:
```
🤖 Loading ML model...
✅ Model loaded in 2.34s
   Threshold: 0.7

🛡️ Layer 1: Rule-based Detection
   Total rules: 34

🤖 Layer 2: ML Detection
   Model: Ensemble (XGBoost + LightGBM + RandomForest)
   Threshold: 0.7
   Training F1: 0.9531

🛡️ HYBRID WAF PROXY STARTED
🌐 WAF listening on: http://localhost:5000
🎯 Backend target: http://localhost:5001
```

### Step 3: Test WAF (in new terminal)

```bash
python attack_sim.py
```

## 🌐 Usage

### Access Protected Application

Instead of accessing backend directly (`http://localhost:5001`), access through WAF:

```
http://localhost:5000
```

All requests will be filtered by 2-layer defense.

### Monitor WAF Activity

**WAF Statistics:**
```
http://localhost:5000/waf/stats
```

Response:
```json
{
  "total_requests": 150,
  "blocked": 45,
  "allowed": 105,
  "detection_rate": "30.00%",
  "layer_1_blocks": 35,
  "layer_2_blocks": 10,
  "rule_detections": {
    "SQL Injection": 20,
    "Cross-Site Scripting (XSS)": 15
  },
  "ml_detections": {
    "SQL Injection (ML)": 7,
    "Suspicious Activity (ML)": 3
  },
  "processing_times": {
    "rule_avg_ms": 1.23,
    "ml_avg_ms": 15.67,
    "total_avg_ms": 3.45
  }
}
```

**Health Check:**
```
http://localhost:5000/waf/health
```

### View Blocked Requests

Check `blocked_requests.jsonl`:

```json
{"timestamp": "2025-11-07T10:30:15", "detector": "Rule-based (Layer 1)", "attack_type": "SQL Injection", "confidence": 1.0, "method": "GET", "url": "/search?q=' UNION SELECT * FROM users--", "ip": "127.0.0.1"}
{"timestamp": "2025-11-07T10:30:16", "detector": "ML-based (Layer 2)", "attack_type": "Suspicious Activity (ML)", "confidence": 0.8234, "method": "POST", "url": "/comment", "ip": "127.0.0.1"}
```

## 🧪 Testing

### Test Normal Requests (should PASS)

```bash
curl http://localhost:5000/
curl http://localhost:5000/api/users
curl http://localhost:5000/search?q=hello
```

### Test SQL Injection (should BLOCK)

```bash
# Layer 1 will block (Rule-based)
curl "http://localhost:5000/search?q=admin' OR '1'='1"
curl "http://localhost:5000/search?q=' UNION SELECT * FROM users--"

# Layer 2 might catch sophisticated variants
curl "http://localhost:5000/search?q=%27%20UNION%20SELECT%20*"
```

### Test XSS (should BLOCK)

```bash
# Layer 1 will block
curl -X POST http://localhost:5000/comment \
  -H "Content-Type: application/json" \
  -d '{"comment": "<script>alert('XSS')</script>"}'

curl "http://localhost:5000/search?q=<img src=x onerror=alert(1)>"
```

### Test Path Traversal (should BLOCK)

```bash
# Layer 1 will block
curl "http://localhost:5000/file?path=../../etc/passwd"
curl "http://localhost:5000/file?path=%2e%2e%2fetc%2fpasswd"
```

## 📈 Performance Tuning

### Adjust ML Threshold

Edit `ml_detector.py` line 45:

```python
self.threshold = 0.7  # Default (F1=86.73%, FPR=0.03%)
```

Options:
- **0.5**: Higher recall (95.85%), more FP (3.68%)
- **0.6**: Balanced (F1=92.64%, FPR=0.49%)
- **0.7**: Optimal (F1=86.73%, FPR=0.03%) ✅ RECOMMENDED
- **0.8**: Fewer FP (FPR=0.00%), more FN (23.40% → 28%)

### Disable Layers

Edit `waf_proxy.py` line 26-27:

```python
ENABLE_RULE_DETECTION = True   # Set to False to disable Layer 1
ENABLE_ML_DETECTION = True     # Set to False to disable Layer 2
```

## 🔍 Monitoring & Logging

### Log Files

1. **waf_proxy.log** - All WAF activity
   ```
   2025-11-07 10:30:15 - INFO - ✅ ALLOWED: GET /api/users | Process time: 1.23ms
   2025-11-07 10:30:16 - WARNING - 🚫 BLOCKED by Rule-based (Layer 1): SQL Injection
   ```

2. **blocked_requests.jsonl** - Detailed blocked requests (JSON Lines format)

### Real-time Monitoring

```bash
# Watch logs
tail -f waf_proxy.log

# Watch blocked requests
tail -f blocked_requests.jsonl
```

## 🐛 Troubleshooting

### "Module not found" error

```bash
pip install -r requirements.txt
```

If no requirements.txt, install manually:
```bash
pip install flask requests joblib scikit-learn scipy xgboost lightgbm imbalanced-learn colorama
```

### "Model file not found"

Verify path in `ml_detector.py` line 21:
```python
model_path: str = "waf_plots/models/firewall_model_bundle.joblib"
```

### Backend connection error

Make sure web_app.py is running on port 5001:
```bash
python web_app.py
```

### Port already in use

Change ports in respective files:
- WAF proxy: `waf_proxy.py` line 225 → `app.run(port=5000)`
- Web app: `web_app.py` line 208 → `app.run(port=5001)`

## 🚀 Production Deployment

### 1. Use Production WSGI Server

Don't use Flask development server! Use Gunicorn or uWSGI:

```bash
# Install
pip install gunicorn

# Run WAF proxy
gunicorn -w 4 -b 0.0.0.0:5000 waf_proxy:app

# Run web app
gunicorn -w 4 -b 0.0.0.0:5001 web_app:app
```

### 2. Add Reverse Proxy (Nginx)

```nginx
upstream waf {
    server 127.0.0.1:5000;
}

server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://waf;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### 3. Enable HTTPS

```bash
certbot --nginx -d your-domain.com
```

### 4. Set up Monitoring

- Log rotation (logrotate)
- Alerting (Prometheus + Grafana)
- Dashboard for WAF stats

### 5. Database for Logs

Instead of JSONL files, use database:
- SQLite (small scale)
- PostgreSQL (production)
- Elasticsearch (large scale + search)

## 📊 Expected Results from attack_sim.py

```
🟢 TESTING NORMAL REQUESTS (Should be ALLOWED)
✅ Home page                    | ALLOWED | 1.2ms
✅ API - Get users              | ALLOWED | 1.5ms
✅ Search - legitimate          | ALLOWED | 1.3ms
...

🔴 TESTING SQL INJECTION ATTACKS (Should be BLOCKED)
✅ SQLi - UNION SELECT          | BLOCKED by Rule-based (Layer 1) | SQL Injection | 1.8ms
✅ SQLi - Boolean (OR 1=1)      | BLOCKED by Rule-based (Layer 1) | SQL Injection | 1.6ms
...

🔴 TESTING XSS ATTACKS (Should be BLOCKED)
✅ XSS - Script tag             | BLOCKED by Rule-based (Layer 1) | XSS | 1.4ms
✅ XSS - IMG onerror            | BLOCKED by Rule-based (Layer 1) | XSS | 1.5ms
...

📊 WAF STATISTICS
Overall Statistics:
   Total requests: 45
   Blocked: 35 (77.78%)
   Allowed: 10

Detection by Layer:
   Layer 1 (Rule-based): 32 blocks
   Layer 2 (ML-based): 3 blocks

Processing Times:
   Rule-based avg: 1.45ms
   ML-based avg: 16.23ms
   Total avg: 3.12ms
```

## 🎉 Success Criteria

✅ **Normal requests pass through** (0% blocking rate for legitimate traffic)  
✅ **SQL Injection attacks blocked** (~100% by Layer 1)  
✅ **XSS attacks blocked** (~100% by Layer 1)  
✅ **Path Traversal blocked** (~100% by Layer 1)  
✅ **Sophisticated attacks caught by ML** (Layer 2 catches 70-80% of what passes Layer 1)  
✅ **Low latency** (<5ms average for normal traffic)  
✅ **No crashes or errors** during testing  

## 📚 Next Steps

1. ✅ Deploy and test system
2. ⏳ Collect production traffic data
3. ⏳ Fine-tune threshold based on FP/FN rate
4. ⏳ Add more rules for specific attack patterns
5. ⏳ Retrain ML model with production data
6. ⏳ Set up monitoring dashboard
7. ⏳ Implement rate limiting
8. ⏳ Add IP reputation scoring

---

**🛡️ Your application is now protected by Hybrid WAF!**
