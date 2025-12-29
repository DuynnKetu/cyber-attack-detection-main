"""
🛡️ Hybrid WAF Proxy - 2-Layer Defense System

Layer 1: Rule-based Detection (Fast, catches 70-80% attacks)
Layer 2: ML Detection (Slower, catches remaining sophisticated attacks)

Total Expected Detection: ~94-95% with <0.04% FP rate
"""

from flask import Flask, request, jsonify, Response, render_template, send_from_directory
import requests
import time
import json
import sys
from datetime import datetime
from rule_detector import RuleDetector
from ml_detector import MLDetector
from typing import Dict, Any
import logging
import os

# Setup logging with UTF-8 encoding
class UTF8StreamHandler(logging.StreamHandler):
    """Custom handler to handle UTF-8 encoding on Windows"""
    def __init__(self):
        super().__init__(sys.stdout)
        # Force UTF-8 encoding for emoji support
        if sys.platform == 'win32':
            try:
                sys.stdout.reconfigure(encoding='utf-8')
            except:
                pass

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('waf_proxy.log', encoding='utf-8'),
        UTF8StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Disable Flask's default request logging for cleaner output
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)  # Only show errors, not every request

app = Flask(__name__, 
            template_folder='templates',
            static_folder='static')

# Configuration
BACKEND_URL = "http://localhost:5001"  # Target web application
ENABLE_RULE_DETECTION = True
ENABLE_ML_DETECTION = True

# Statistics
stats = {
    "total_requests": 0,
    "blocked_by_rules": 0,
    "blocked_by_ml": 0,
    "allowed": 0,
    "rule_detections": {},
    "ml_detections": {},
    "processing_times": {
        "rule_avg": 0,
        "ml_avg": 0,
        "total_avg": 0
    }
}

# Initialize detectors
logger.info("=" * 80)
logger.info("🚀 INITIALIZING HYBRID WAF PROXY")
logger.info("=" * 80)

rule_detector = RuleDetector() if ENABLE_RULE_DETECTION else None
ml_detector = MLDetector() if ENABLE_ML_DETECTION else None

if rule_detector:
    rule_stats = rule_detector.get_stats()
    logger.info(f"\n🛡️  Layer 1: Rule-based Detection")
    logger.info(f"   Total rules: {rule_stats['total_rules']}")
    logger.info(f"   - SQL Injection: {rule_stats['sqli_rules']}")
    logger.info(f"   - XSS: {rule_stats['xss_rules']}")
    logger.info(f"   - Path Traversal: {rule_stats['path_traversal_rules']}")
    logger.info(f"   - Command Injection: {rule_stats['cmd_injection_rules']}")
    logger.info(f"   - LDAP: {rule_stats['ldap_rules']}")
    logger.info(f"   - XXE: {rule_stats['xxe_rules']}")

if ml_detector:
    ml_stats = ml_detector.get_stats()
    logger.info(f"\n🤖 Layer 2: ML Detection")
    logger.info(f"   Model: {ml_stats['model_type']}")
    logger.info(f"   Threshold: {ml_stats['threshold']}")
    logger.info(f"   Training F1: {ml_stats['training_f1']:.4f}")
    logger.info(f"   Training AUC: {ml_stats['training_auc']:.4f}")
    logger.info(f"   Total features: {ml_stats['total_features']:,}")

logger.info("\n" + "=" * 80)
logger.info("✅ WAF PROXY READY!")
logger.info("=" * 80)


def log_detection(req_data: Dict[str, Any], detector: str, attack_type: str, confidence: float):
    """Log blocked request"""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "status": "blocked",
        "detector": detector,
        "attack_type": attack_type,
        "confidence": confidence,
        "method": req_data['method'],
        "url": req_data['url'],
        "content": req_data['content'][:200],  # Truncate
        "ip": req_data['ip']
    }
    
    logger.warning(f"🚫 BLOCKED by {detector}: {attack_type} | {req_data['url']} | Confidence: {confidence:.4f}")
    
    # Save to file
    with open('waf_requests.jsonl', 'a', encoding='utf-8') as f:
        f.write(json.dumps(log_entry) + '\n')


def log_allowed(req_data: Dict[str, Any]):
    """Log allowed request"""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "status": "allowed",
        "detector": "N/A",
        "attack_type": "N/A",
        "confidence": 0,
        "method": req_data['method'],
        "url": req_data['url'],
        "content": req_data['content'][:200],  # Truncate
        "ip": req_data['ip']
    }
    
    # Save to file
    with open('waf_requests.jsonl', 'a', encoding='utf-8') as f:
        f.write(json.dumps(log_entry) + '\n')


def create_block_response(detector: str, attack_type: str, confidence: float) -> Response:
    """Create 403 Forbidden response"""
    response = {
        "error": "Request blocked by WAF",
        "detector": detector,
        "attack_type": attack_type,
        "confidence": round(confidence, 4),
        "timestamp": datetime.now().isoformat()
    }
    
    return jsonify(response), 403


@app.before_request
def waf_filter():
    """Main WAF filtering logic - 2-layer defense"""
    global stats
    
    # Whitelist: Skip WAF filtering for internal endpoints
    WHITELIST_PATHS = [
        '/dashboard',
        '/waf/stats',
        '/waf/health',
        '/waf/logs',
        '/waf/clear-logs',
        '/static/'
    ]
    
    # Check if request path is whitelisted
    request_path = request.path
    if any(request_path.startswith(path) for path in WHITELIST_PATHS):
        return  # Skip WAF filtering
    
    start_time = time.time()
    stats["total_requests"] += 1
    
    # Extract request data
    url = request.url.replace(request.host_url.rstrip('/'), '')  # Remove host
    content = request.get_data(as_text=True)
    method = request.method
    ip = request.remote_addr
    
    req_data = {
        "url": url,
        "content": content,
        "method": method,
        "ip": ip
    }
    
    # ========== LAYER 1: RULE-BASED DETECTION ==========
    if ENABLE_RULE_DETECTION and rule_detector:
        rule_start = time.time()
        is_attack, attack_type, confidence = rule_detector.detect(url, content, method)
        rule_time = (time.time() - rule_start) * 1000  # ms
        
        if is_attack:
            stats["blocked_by_rules"] += 1
            stats["rule_detections"][attack_type] = stats["rule_detections"].get(attack_type, 0) + 1
            
            # Update average processing time
            total_rule_time = stats["processing_times"]["rule_avg"] * (stats["blocked_by_rules"] - 1)
            stats["processing_times"]["rule_avg"] = (total_rule_time + rule_time) / stats["blocked_by_rules"]
            
            log_detection(req_data, "Rule-based (Layer 1)", attack_type, confidence)
            return create_block_response("Rule-based (Layer 1)", attack_type, confidence)
    
    # ========== LAYER 2: ML DETECTION ==========
    # Only check ML if passed rule-based filter
    if ENABLE_ML_DETECTION and ml_detector:
        ml_start = time.time()
        is_attack, attack_type, confidence = ml_detector.detect(url, content, method)
        ml_time = (time.time() - ml_start) * 1000  # ms
        
        if is_attack:
            stats["blocked_by_ml"] += 1
            stats["ml_detections"][attack_type] = stats["ml_detections"].get(attack_type, 0) + 1
            
            # Update average processing time
            total_ml_time = stats["processing_times"]["ml_avg"] * (stats["blocked_by_ml"] - 1)
            stats["processing_times"]["ml_avg"] = (total_ml_time + ml_time) / stats["blocked_by_ml"]
            
            log_detection(req_data, "ML-based (Layer 2)", attack_type, confidence)
            return create_block_response("ML-based (Layer 2)", attack_type, confidence)
    
    # Request is clean - allow
    stats["allowed"] += 1
    total_time = (time.time() - start_time) * 1000
    
    # Update total average processing time
    total_proc_time = stats["processing_times"]["total_avg"] * (stats["total_requests"] - 1)
    stats["processing_times"]["total_avg"] = (total_proc_time + total_time) / stats["total_requests"]
    
    # Log allowed request
    log_allowed(req_data)
    
    logger.info(f"✅ ALLOWED: {method} {url} | Process time: {total_time:.2f}ms")


@app.route('/waf/stats', methods=['GET'])
def get_stats():
    """Get WAF statistics"""
    detection_rate = 0
    if stats["total_requests"] > 0:
        blocked = stats["blocked_by_rules"] + stats["blocked_by_ml"]
        detection_rate = (blocked / stats["total_requests"]) * 100
    
    response = {
        "total_requests": stats["total_requests"],
        "blocked": stats["blocked_by_rules"] + stats["blocked_by_ml"],
        "allowed": stats["allowed"],
        "detection_rate": f"{detection_rate:.2f}%",
        "layer_1_blocks": stats["blocked_by_rules"],
        "layer_2_blocks": stats["blocked_by_ml"],
        "rule_detections": stats["rule_detections"],
        "ml_detections": stats["ml_detections"],
        "processing_times": {
            "rule_avg_ms": round(stats["processing_times"]["rule_avg"], 2),
            "ml_avg_ms": round(stats["processing_times"]["ml_avg"], 2),
            "total_avg_ms": round(stats["processing_times"]["total_avg"], 2)
        }
    }
    
    return jsonify(response)


@app.route('/waf/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "rule_detector": "enabled" if ENABLE_RULE_DETECTION else "disabled",
        "ml_detector": "enabled" if ENABLE_ML_DETECTION else "disabled",
        "timestamp": datetime.now().isoformat()
    })


@app.route('/dashboard')
def dashboard():
    """WAF Dashboard UI"""
    return render_template('dashboard.html')


@app.route('/waf/logs', methods=['GET'])
def get_logs():
    """Get recent requests logs (both blocked and allowed)"""
    try:
        logs = []
        if os.path.exists('waf_requests.jsonl'):
            with open('waf_requests.jsonl', 'r', encoding='utf-8') as f:
                # Read last 100 lines
                lines = f.readlines()[-100:]
                for line in lines:
                    try:
                        logs.append(json.loads(line))
                    except:
                        pass
        
        return jsonify({
            "logs": logs,
            "count": len(logs)
        })
    except Exception as e:
        logger.error(f"Error fetching logs: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/waf/clear-logs', methods=['POST'])
def clear_logs():
    """Clear all requests logs"""
    try:
        # Delete the log file if it exists
        if os.path.exists('waf_requests.jsonl'):
            os.remove('waf_requests.jsonl')
            logger.info("🗑️  Logs cleared by user")
        
        return jsonify({
            "success": True,
            "message": "Logs cleared successfully"
        })
    except Exception as e:
        logger.error(f"Error clearing logs: {str(e)}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# Proxy all other requests to backend
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    """Forward clean requests to backend"""
    # Construct backend URL
    backend_url = f"{BACKEND_URL}/{path}"
    
    # Forward request
    try:
        resp = requests.request(
            method=request.method,
            url=backend_url,
            headers={key: value for key, value in request.headers if key.lower() != 'host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=30
        )
        
        # Return backend response
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for name, value in resp.raw.headers.items()
                   if name.lower() not in excluded_headers]
        
        return Response(resp.content, resp.status_code, headers)
    
    except requests.exceptions.ConnectionError:
        logger.error(f"❌ Backend connection error: {backend_url}")
        return jsonify({"error": "Backend service unavailable"}), 503
    
    except Exception as e:
        logger.error(f"❌ Proxy error: {str(e)}")
        return jsonify({"error": "Internal proxy error"}), 500


if __name__ == '__main__':
    # Run WAF proxy
    print("\n" + "=" * 80)
    print("🛡️  HYBRID WAF PROXY STARTED")
    print("=" * 80)
    print(f"\n🌐 WAF listening on: http://localhost:5000")
    print(f"🎯 Backend target: {BACKEND_URL}")
    print(f"\n📊 Dashboard: http://localhost:5000/dashboard")
    print(f"📈 Stats API: http://localhost:5000/waf/stats")
    print(f"💚 Health check: http://localhost:5000/waf/health")
    print(f"\n⚙️  Configuration:")
    print(f"   - Rule-based detection: {'✅ Enabled' if ENABLE_RULE_DETECTION else '❌ Disabled'}")
    print(f"   - ML detection: {'✅ Enabled' if ENABLE_ML_DETECTION else '❌ Disabled'}")
    print(f"\n🚀 Press Ctrl+C to stop\n")
    print("=" * 80)
    
    app.run(host='0.0.0.0', port=5000, debug=False)
