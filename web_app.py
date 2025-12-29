"""
🌐 Simple Web Application - Backend Server

Đây là web app mẫu để test WAF
Port: 5001
"""

from flask import Flask, request, jsonify, render_template_string
import sqlite3
from datetime import datetime

app = Flask(__name__)

# Initialize database
def init_db():
    conn = sqlite3.connect('webapp.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    ''')
    
    # Insert sample data
    try:
        cursor.execute("INSERT INTO users (username, email, created_at) VALUES (?, ?, ?)",
                      ("admin", "admin@example.com", datetime.now().isoformat()))
        cursor.execute("INSERT INTO users (username, email, created_at) VALUES (?, ?, ?)",
                      ("john", "john@example.com", datetime.now().isoformat()))
        cursor.execute("INSERT INTO users (username, email, created_at) VALUES (?, ?, ?)",
                      ("jane", "jane@example.com", datetime.now().isoformat()))
    except sqlite3.IntegrityError:
        pass  # Data already exists
    
    conn.commit()
    conn.close()

init_db()

# HTML Templates
HOME_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Sample Web App</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
        }
        h1 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 2.5em;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 1.1em;
        }
        .card {
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }
        .card h3 {
            color: #667eea;
            margin-bottom: 10px;
        }
        .btn {
            background: #667eea;
            color: white;
            padding: 12px 30px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1em;
            margin: 5px;
            text-decoration: none;
            display: inline-block;
            transition: all 0.3s;
        }
        .btn:hover {
            background: #764ba2;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        .endpoints {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }
        .endpoint {
            background: white;
            padding: 20px;
            border-radius: 10px;
            border: 2px solid #e0e0e0;
        }
        .endpoint h4 {
            color: #667eea;
            margin-bottom: 10px;
        }
        .method {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            margin-right: 10px;
        }
        .method.get { background: #28a745; color: white; }
        .method.post { background: #007bff; color: white; }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #e0e0e0;
            text-align: center;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 Sample Web Application</h1>
        <p class="subtitle">Protected by Hybrid WAF (Rule-based + ML)</p>
        
        <div class="card">
            <h3>🛡️ Security Status</h3>
            <p>This application is protected by a 2-layer hybrid WAF system:</p>
            <ul style="margin-left: 20px; margin-top: 10px;">
                <li><strong>Layer 1:</strong> Rule-based detection (catches 70-80% attacks)</li>
                <li><strong>Layer 2:</strong> ML-based detection (catches sophisticated attacks)</li>
            </ul>
        </div>
        
        <div class="card">
            <h3>📊 Available Endpoints</h3>
            <div class="endpoints">
                <div class="endpoint">
                    <h4><span class="method get">GET</span> /</h4>
                    <p>Home page (this page)</p>
                </div>
                <div class="endpoint">
                    <h4><span class="method get">GET</span> /api/users</h4>
                    <p>Get all users from database</p>
                </div>
                <div class="endpoint">
                    <h4><span class="method get">GET</span> /search</h4>
                    <p>Search functionality (vulnerable to SQLi without WAF)</p>
                </div>
                <div class="endpoint">
                    <h4><span class="method post">POST</span> /comment</h4>
                    <p>Submit comment (vulnerable to XSS without WAF)</p>
                </div>
                <div class="endpoint">
                    <h4><span class="method get">GET</span> /file</h4>
                    <p>File access (vulnerable to Path Traversal without WAF)</p>
                </div>
                <div class="endpoint">
                    <h4><span class="method get">GET</span> /health</h4>
                    <p>Application health check</p>
                </div>
            </div>
        </div>
        
        <div style="text-align: center; margin-top: 30px;">
            <a href="/api/users" class="btn">👥 View Users</a>
            <a href="/search?q=test" class="btn">🔍 Test Search</a>
            <a href="/health" class="btn">💚 Health Check</a>
        </div>
        
        <div class="footer">
            <p>🛡️ Powered by Hybrid WAF (Rule-based + ML Detection)</p>
            <p style="margin-top: 10px; font-size: 0.9em;">
                WAF Stats: <a href="http://localhost:5000/waf/stats" target="_blank">http://localhost:5000/waf/stats</a>
            </p>
        </div>
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    """Home page"""
    return render_template_string(HOME_TEMPLATE)


@app.route('/api/users', methods=['GET'])
def get_users():
    """Get all users - REST API endpoint"""
    conn = sqlite3.connect('webapp.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, username, email, created_at FROM users")
    users = cursor.fetchall()
    conn.close()
    
    users_list = [
        {
            "id": user[0],
            "username": user[1],
            "email": user[2],
            "created_at": user[3]
        }
        for user in users
    ]
    
    return jsonify({
        "success": True,
        "users": users_list,
        "count": len(users_list)
    })


@app.route('/search', methods=['GET'])
def search():
    """Search endpoint - VULNERABLE to SQLi without WAF"""
    query = request.args.get('q', '')
    
    conn = sqlite3.connect('webapp.db')
    cursor = conn.cursor()
    
    # VULNERABLE SQL query (for demonstration)
    # In production, ALWAYS use parameterized queries!
    try:
        # This is intentionally vulnerable for WAF testing
        sql = f"SELECT username, email FROM users WHERE username LIKE '%{query}%'"
        cursor.execute(sql)
        results = cursor.fetchall()
        
        return jsonify({
            "success": True,
            "query": query,
            "results": [{"username": r[0], "email": r[1]} for r in results]
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500
    finally:
        conn.close()


@app.route('/comment', methods=['POST'])
def add_comment():
    """Add comment - VULNERABLE to XSS without WAF"""
    data = request.get_json() or {}
    comment = data.get('comment', '')
    
    # In production, ALWAYS sanitize user input!
    # This is intentionally vulnerable for WAF testing
    
    return jsonify({
        "success": True,
        "message": "Comment added",
        "comment": comment,  # Echo back (vulnerable to XSS)
        "timestamp": datetime.now().isoformat()
    })


@app.route('/file', methods=['GET'])
def get_file():
    """File access - VULNERABLE to Path Traversal without WAF"""
    filepath = request.args.get('path', '')
    
    # In production, NEVER allow user-controlled file paths!
    # This is intentionally vulnerable for WAF testing
    
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        return jsonify({
            "success": True,
            "filepath": filepath,
            "content": content[:500]  # Limit output
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400


@app.route('/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({
        "status": "healthy",
        "service": "Sample Web Application",
        "timestamp": datetime.now().isoformat()
    })


if __name__ == '__main__':
    print("\n" + "=" * 80)
    print("🌐 SAMPLE WEB APPLICATION STARTED")
    print("=" * 80)
    print(f"\n🚀 Application running on: http://localhost:5001")
    print(f"\n📋 Endpoints:")
    print(f"   - GET  /                    → Home page")
    print(f"   - GET  /api/users           → Get all users")
    print(f"   - GET  /search?q=<query>    → Search (vulnerable to SQLi)")
    print(f"   - POST /comment             → Add comment (vulnerable to XSS)")
    print(f"   - GET  /file?path=<path>    → File access (vulnerable to Path Traversal)")
    print(f"   - GET  /health              → Health check")
    print(f"\n⚠️  Note: This app is INTENTIONALLY VULNERABLE for WAF testing!")
    print(f"   Access through WAF proxy: http://localhost:5000")
    print(f"\n🛡️  Press Ctrl+C to stop\n")
    print("=" * 80)
    
    app.run(host='0.0.0.0', port=5001, debug=False)
