"""
🧪 Attack Simulator - Test Hybrid WAF System

Gửi requests (normal + attacks) để test WAF
"""

import requests
import json
import time
from colorama import init, Fore, Style

init(autoreset=True)

WAF_URL = "http://localhost:5000"

def print_result(test_name: str, expected: str, response, start_time: float):
    """Print test result"""
    elapsed = (time.time() - start_time) * 1000
    
    if response.status_code == 403:
        # Blocked
        data = response.json()
        detector = data.get('detector', 'Unknown')
        attack_type = data.get('attack_type', 'Unknown')
        confidence = data.get('confidence', 0)
        
        if expected == "BLOCK":
            print(f"{Fore.GREEN}✅ {test_name:50} | BLOCKED by {detector:25} | {attack_type:30} | Confidence: {confidence:.4f} | {elapsed:.1f}ms")
        else:
            print(f"{Fore.RED}❌ {test_name:50} | FALSE POSITIVE by {detector:25} | {attack_type:30} | {elapsed:.1f}ms")
    else:
        # Allowed
        if expected == "ALLOW":
            print(f"{Fore.GREEN}✅ {test_name:50} | ALLOWED{' ' * 60} | {elapsed:.1f}ms")
        else:
            print(f"{Fore.RED}❌ {test_name:50} | FALSE NEGATIVE (should be blocked){' ' * 30} | {elapsed:.1f}ms")


def test_normal_requests():
    """Test normal requests - should all PASS"""
    print(f"\n{Fore.CYAN}{'=' * 120}")
    print(f"{Fore.CYAN}🟢 TESTING NORMAL REQUESTS (Should be ALLOWED)")
    print(f"{Fore.CYAN}{'=' * 120}\n")
    
    tests = [
        ("Home page", "/", "GET", None),
        ("API - Get users", "/api/users", "GET", None),
        ("Search - legitimate", "/search?q=john", "GET", None),
        ("Search - with spaces", "/search?q=hello%20world", "GET", None),
        ("File - safe path", "/file?path=README.md", "GET", None),
        ("Health check", "/health", "GET", None),
        ("Comment - normal", "/comment", "POST", {"comment": "Great article!"}),
        ("Comment - JSON", "/comment", "POST", {"comment": "Thanks for sharing"}),
    ]
    
    for test_name, path, method, data in tests:
        url = f"{WAF_URL}{path}"
        start_time = time.time()
        
        try:
            if method == "GET":
                response = requests.get(url, timeout=5)
            else:
                response = requests.post(url, json=data, timeout=5)
            
            print_result(test_name, "ALLOW", response, start_time)
        
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}❌ {test_name:50} | CONNECTION ERROR - Is WAF running?")
        except Exception as e:
            print(f"{Fore.RED}❌ {test_name:50} | ERROR: {str(e)}")


def test_sqli_attacks():
    """Test SQL Injection attacks - should all be BLOCKED"""
    print(f"\n{Fore.CYAN}{'=' * 120}")
    print(f"{Fore.CYAN}🔴 TESTING SQL INJECTION ATTACKS (Should be BLOCKED)")
    print(f"{Fore.CYAN}{'=' * 120}\n")
    
    tests = [
        ("SQLi - UNION SELECT", "/search?q=' UNION SELECT * FROM users--", "GET", None),
        ("SQLi - Boolean (OR 1=1)", "/search?q=admin' OR '1'='1", "GET", None),
        ("SQLi - Boolean (AND 1=1)", "/search?q=test' AND '1'='1'--", "GET", None),
        ("SQLi - Stacked queries", "/search?q=1; DROP TABLE users--", "GET", None),
        ("SQLi - Comment bypass", "/search?q=admin'--", "GET", None),
        ("SQLi - UNION encoded", "/search?q=%27%20UNION%20SELECT%20*%20FROM%20users--", "GET", None),
        ("SQLi - Information schema", "/search?q=' UNION SELECT table_name FROM information_schema.tables--", "GET", None),
        ("SQLi - Time-based", "/search?q=1' AND SLEEP(5)--", "GET", None),
        ("SQLi - Error-based", "/search?q=1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x23,FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)y)--", "GET", None),
    ]
    
    for test_name, path, method, data in tests:
        url = f"{WAF_URL}{path}"
        start_time = time.time()
        
        try:
            if method == "GET":
                response = requests.get(url, timeout=5)
            else:
                response = requests.post(url, json=data, timeout=5)
            
            print_result(test_name, "BLOCK", response, start_time)
        
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}❌ {test_name:50} | CONNECTION ERROR")
        except Exception as e:
            print(f"{Fore.RED}❌ {test_name:50} | ERROR: {str(e)}")


def test_xss_attacks():
    """Test XSS attacks - should all be BLOCKED"""
    print(f"\n{Fore.CYAN}{'=' * 120}")
    print(f"{Fore.CYAN}🔴 TESTING XSS ATTACKS (Should be BLOCKED)")
    print(f"{Fore.CYAN}{'=' * 120}\n")
    
    tests = [
        ("XSS - Script tag", "/comment", "POST", {"comment": "<script>alert('XSS')</script>"}),
        ("XSS - IMG onerror", "/search?q=<img src=x onerror=alert(1)>", "GET", None),
        ("XSS - SVG onload", "/comment", "POST", {"comment": "<svg onload=alert(1)>"}),
        ("XSS - JavaScript protocol", "/search?q=<a href='javascript:alert(1)'>click</a>", "GET", None),
        ("XSS - Event handler", "/comment", "POST", {"comment": "<div onclick=alert(1)>click</div>"}),
        ("XSS - Obfuscated", "/comment", "POST", {"comment": "<svg/onload=alert(1)>"}),
        ("XSS - Data URL", "/search?q=<object data='data:text/html,<script>alert(1)</script>'>", "GET", None),
        ("XSS - Iframe", "/comment", "POST", {"comment": "<iframe src='javascript:alert(1)'>"}),
    ]
    
    for test_name, path, method, data in tests:
        url = f"{WAF_URL}{path}"
        start_time = time.time()
        
        try:
            if method == "GET":
                response = requests.get(url, timeout=5)
            else:
                response = requests.post(url, json=data, timeout=5)
            
            print_result(test_name, "BLOCK", response, start_time)
        
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}❌ {test_name:50} | CONNECTION ERROR")
        except Exception as e:
            print(f"{Fore.RED}❌ {test_name:50} | ERROR: {str(e)}")


def test_path_traversal_attacks():
    """Test Path Traversal attacks - should all be BLOCKED"""
    print(f"\n{Fore.CYAN}{'=' * 120}")
    print(f"{Fore.CYAN}🔴 TESTING PATH TRAVERSAL ATTACKS (Should be BLOCKED)")
    print(f"{Fore.CYAN}{'=' * 120}\n")
    
    tests = [
        ("Path Traversal - Basic", "/file?path=../../etc/passwd", "GET", None),
        ("Path Traversal - Windows", "/file?path=..\\..\\windows\\system32\\config\\sam", "GET", None),
        ("Path Traversal - Encoded", "/file?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd", "GET", None),
        ("Path Traversal - Absolute", "/file?path=/etc/shadow", "GET", None),
        ("Path Traversal - Multiple", "/file?path=../../../../etc/passwd", "GET", None),
    ]
    
    for test_name, path, method, data in tests:
        url = f"{WAF_URL}{path}"
        start_time = time.time()
        
        try:
            if method == "GET":
                response = requests.get(url, timeout=5)
            else:
                response = requests.post(url, json=data, timeout=5)
            
            print_result(test_name, "BLOCK", response, start_time)
        
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}❌ {test_name:50} | CONNECTION ERROR")
        except Exception as e:
            print(f"{Fore.RED}❌ {test_name:50} | ERROR: {str(e)}")


def get_waf_stats():
    """Get and display WAF statistics"""
    print(f"\n{Fore.CYAN}{'=' * 120}")
    print(f"{Fore.CYAN}📊 WAF STATISTICS")
    print(f"{Fore.CYAN}{'=' * 120}\n")
    
    try:
        response = requests.get(f"{WAF_URL}/waf/stats", timeout=5)
        stats = response.json()
        
        print(f"{Fore.YELLOW}Overall Statistics:")
        print(f"   Total requests: {stats['total_requests']}")
        print(f"   Blocked: {stats['blocked']} ({stats['detection_rate']})")
        print(f"   Allowed: {stats['allowed']}")
        
        print(f"\n{Fore.YELLOW}Detection by Layer:")
        print(f"   Layer 1 (Rule-based): {stats['layer_1_blocks']} blocks")
        print(f"   Layer 2 (ML-based): {stats['layer_2_blocks']} blocks")
        
        if stats['rule_detections']:
            print(f"\n{Fore.YELLOW}Rule-based Detections:")
            for attack_type, count in stats['rule_detections'].items():
                print(f"   {attack_type}: {count}")
        
        if stats['ml_detections']:
            print(f"\n{Fore.YELLOW}ML-based Detections:")
            for attack_type, count in stats['ml_detections'].items():
                print(f"   {attack_type}: {count}")
        
        print(f"\n{Fore.YELLOW}Processing Times:")
        print(f"   Rule-based avg: {stats['processing_times']['rule_avg_ms']:.2f}ms")
        print(f"   ML-based avg: {stats['processing_times']['ml_avg_ms']:.2f}ms")
        print(f"   Total avg: {stats['processing_times']['total_avg_ms']:.2f}ms")
    
    except Exception as e:
        print(f"{Fore.RED}❌ Error getting stats: {str(e)}")


if __name__ == "__main__":
    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{'=' * 120}")
    print(f"{Fore.MAGENTA}{Style.BRIGHT}🧪 HYBRID WAF ATTACK SIMULATOR")
    print(f"{Fore.MAGENTA}{Style.BRIGHT}{'=' * 120}\n")
    
    print(f"{Fore.YELLOW}Testing WAF at: {WAF_URL}")
    print(f"{Fore.YELLOW}Make sure both WAF proxy (port 5000) and web app (port 5001) are running!\n")
    
    input(f"{Fore.CYAN}Press Enter to start testing...")
    
    # Run tests
    test_normal_requests()
    test_sqli_attacks()
    test_xss_attacks()
    test_path_traversal_attacks()
    
    # Get statistics
    get_waf_stats()
    
    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{'=' * 120}")
    print(f"{Fore.MAGENTA}{Style.BRIGHT}✅ ALL TESTS COMPLETED!")
    print(f"{Fore.MAGENTA}{Style.BRIGHT}{'=' * 120}\n")
