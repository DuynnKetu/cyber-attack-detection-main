"""
🛡️ Rule-based Attack Detection - Layer 1 (Fast Filter)

Chặn 70-80% attacks rõ ràng bằng pattern matching
Process time: ~1-2ms per request
"""

import re
from typing import Tuple, Optional

class RuleDetector:
    """Rule-based detector for common web attacks"""
    
    def __init__(self):
        # SQL Injection patterns
        self.sqli_patterns = [
            # UNION-based SQLi
            re.compile(r"union\s+(all\s+)?select", re.IGNORECASE),
            
            # Boolean-based SQLi
            re.compile(r"(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.IGNORECASE),
            re.compile(r"(or|and)\s+['\"]?[a-z]+['\"]?\s*=\s*['\"]?[a-z]+", re.IGNORECASE),
            
            # Time-based SQLi
            re.compile(r"(sleep|benchmark|waitfor)\s*\(", re.IGNORECASE),
            
            # Stacked queries
            re.compile(r";\s*(drop|delete|update|insert|create|alter)\s+", re.IGNORECASE),
            
            # SQL comments
            re.compile(r"--[\s\r\n]|/\*.*?\*/|#[\s\r\n]"),
            
            # Common SQL functions in unexpected contexts
            re.compile(r"(concat|char|cast|convert|exec|execute)\s*\(", re.IGNORECASE),
            
            # Information schema access
            re.compile(r"information_schema", re.IGNORECASE),
            
            # System tables
            re.compile(r"(sys\.|sysobjects|syscolumns)", re.IGNORECASE),
        ]
        
        # XSS patterns
        self.xss_patterns = [
            # Script tags
            re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
            re.compile(r"<script[^>]*>", re.IGNORECASE),
            
            # Event handlers
            re.compile(r"on(error|load|click|mouseover|focus|blur)\s*=", re.IGNORECASE),
            
            # JavaScript protocol
            re.compile(r"javascript\s*:", re.IGNORECASE),
            re.compile(r"vbscript\s*:", re.IGNORECASE),
            
            # Common XSS functions
            re.compile(r"(alert|prompt|confirm|eval)\s*\(", re.IGNORECASE),
            
            # Dangerous tags
            re.compile(r"<(iframe|embed|object|svg|img)[^>]*>", re.IGNORECASE),
            
            # Expression
            re.compile(r"expression\s*\(", re.IGNORECASE),
            
            # Data URLs
            re.compile(r"data:text/html", re.IGNORECASE),
        ]
        
        # Path Traversal patterns
        self.path_traversal_patterns = [
            # Basic traversal
            re.compile(r"\.\./"),
            re.compile(r"\.\.\\"),
            
            # Encoded traversal
            re.compile(r"%2e%2e[/\\]", re.IGNORECASE),
            re.compile(r"\.%2e[/\\]", re.IGNORECASE),
            
            # Absolute paths
            re.compile(r"(/etc/passwd|/etc/shadow|/windows/system32)", re.IGNORECASE),
            
            # File access
            re.compile(r"(file://|file:///)", re.IGNORECASE),
        ]
        
        # Command Injection patterns
        self.cmd_injection_patterns = [
            # Shell commands
            re.compile(r"[;&|]\s*(cat|ls|dir|type|net|ping|wget|curl)\s+", re.IGNORECASE),
            
            # Command separators
            re.compile(r"[;&|`$]\s*\w+"),
            
            # Backticks
            re.compile(r"`[^`]+`"),
        ]
        
        # LDAP Injection patterns
        self.ldap_patterns = [
            re.compile(r"\(\|", re.IGNORECASE),
            re.compile(r"\(&", re.IGNORECASE),
            re.compile(r"\(!", re.IGNORECASE),
        ]
        
        # XXE patterns
        self.xxe_patterns = [
            re.compile(r"<!ENTITY", re.IGNORECASE),
            re.compile(r"<!DOCTYPE", re.IGNORECASE),
            re.compile(r"SYSTEM\s+['\"]", re.IGNORECASE),
        ]
    
    def detect(self, url: str, content: str = "", method: str = "GET") -> Tuple[bool, Optional[str], float]:
        """
        Detect attacks using rule-based patterns
        
        Args:
            url: Request URL
            content: Request body/content
            method: HTTP method
            
        Returns:
            (is_attack, attack_type, confidence)
        """
        full_request = f"{url} {content}"
        
        # Check SQL Injection
        for pattern in self.sqli_patterns:
            if pattern.search(full_request):
                return True, "SQL Injection", 1.0
        
        # Check XSS
        for pattern in self.xss_patterns:
            if pattern.search(full_request):
                return True, "Cross-Site Scripting (XSS)", 1.0
        
        # Check Path Traversal
        for pattern in self.path_traversal_patterns:
            if pattern.search(full_request):
                return True, "Path Traversal", 1.0
        
        # Check Command Injection
        for pattern in self.cmd_injection_patterns:
            if pattern.search(full_request):
                return True, "Command Injection", 1.0
        
        # Check LDAP Injection
        for pattern in self.ldap_patterns:
            if pattern.search(full_request):
                return True, "LDAP Injection", 1.0
        
        # Check XXE
        for pattern in self.xxe_patterns:
            if pattern.search(full_request):
                return True, "XXE (XML External Entity)", 1.0
        
        # No attack detected
        return False, None, 0.0
    
    def get_stats(self) -> dict:
        """Get detector statistics"""
        return {
            "sqli_rules": len(self.sqli_patterns),
            "xss_rules": len(self.xss_patterns),
            "path_traversal_rules": len(self.path_traversal_patterns),
            "cmd_injection_rules": len(self.cmd_injection_patterns),
            "ldap_rules": len(self.ldap_patterns),
            "xxe_rules": len(self.xxe_patterns),
            "total_rules": (
                len(self.sqli_patterns) + 
                len(self.xss_patterns) + 
                len(self.path_traversal_patterns) +
                len(self.cmd_injection_patterns) +
                len(self.ldap_patterns) +
                len(self.xxe_patterns)
            )
        }


if __name__ == "__main__":
    # Test
    detector = RuleDetector()
    
    print("=" * 80)
    print("🛡️  RULE-BASED DETECTOR - TEST")
    print("=" * 80)
    
    test_cases = [
        # Normal requests
        ("/index.php?page=home", "", "Normal"),
        ("/api/users", '{"name":"John"}', "Normal"),
        
        # SQL Injection
        ("/login?user=admin' OR '1'='1", "", "SQLi"),
        ("/search?q=' UNION SELECT * FROM users--", "", "SQLi"),
        
        # XSS
        ("/comment", "<script>alert('XSS')</script>", "XSS"),
        ("/search?q=<img src=x onerror=alert(1)>", "", "XSS"),
        
        # Path Traversal
        ("/file?path=../../etc/passwd", "", "Path Traversal"),
    ]
    
    print(f"\n📊 Testing {len(test_cases)} samples...\n")
    
    for url, content, expected in test_cases:
        is_attack, attack_type, confidence = detector.detect(url, content)
        
        status = "✅" if (is_attack and "Normal" not in expected) or (not is_attack and "Normal" in expected) else "❌"
        
        print(f"{status} {expected:20} | {url[:50]:50}")
        if is_attack:
            print(f"   → Detected: {attack_type} (confidence: {confidence:.2f})")
        print()
    
    # Stats
    stats = detector.get_stats()
    print("=" * 80)
    print(f"📈 DETECTOR STATS:")
    for key, value in stats.items():
        print(f"   {key}: {value}")
    print("=" * 80)
