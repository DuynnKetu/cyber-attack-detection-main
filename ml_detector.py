"""
🤖 ML-based Attack Detection - Layer 2 (Deep Analysis)

Phát hiện sophisticated attacks mà rules bỏ lỡ
Process time: ~10-20ms per request
Threshold: 0.7 (tuned for optimal FP/FN balance)
"""

import joblib
import numpy as np
import pandas as pd
import re
from scipy import sparse
from scipy.stats import entropy as scipy_entropy
from collections import Counter
from typing import Tuple, Optional
import time


class MLDetector:
    """ML-based attack detector using trained ensemble model"""
    
    def __init__(self, model_path: str = "waf_plots/models/firewall_model_bundle.joblib"):
        """
        Load trained model bundle
        
        Args:
            model_path: Path to model bundle file
        """
        print("🤖 Loading ML model...")
        start_time = time.time()
        
        # Load model bundle
        self.bundle = joblib.load(model_path)
        
        self.model = self.bundle['model']
        self.tfidf_vectorizer = self.bundle['tfidf_vectorizer']
        self.method_encoder = self.bundle['method_encoder']
        self.stat_feature_names = self.bundle['stat_feature_names']
        self.config = self.bundle['config']
        self.metrics = self.bundle['metrics']
        
        # Tuned threshold (from analysis)
        self.threshold = 0.7  # Optimal balance: F1=86.73%, FPR=0.03%, FNR=23.40%
        
        load_time = time.time() - start_time
        print(f"✅ Model loaded in {load_time:.2f}s")
        print(f"   Threshold: {self.threshold}")
        print(f"   Training metrics: F1={self.metrics['f1_score']:.4f}, AUC={self.metrics['auc_roc']:.4f}")
    
    def extract_statistical_features(self, url: str, content: str, method: str) -> dict:
        """Extract statistical features from request"""
        full_request = f"{url} {content}"
        
        features = {}
        
        # 1. Length features
        features['url_length'] = len(url)
        features['content_length'] = len(content)
        features['total_length'] = features['url_length'] + features['content_length']
        
        # 2. Special characters count
        special_chars = ["'", '"', '<', '>', '-', ';', '=', '&', '%', '(', ')', '*', '+', '|', '\\', '/', ':', '?', '[', ']', '{', '}']
        for char in special_chars:
            col_name = f'count_{char}' if char not in ["'", '"'] else f'count_{ord(char)}'
            features[col_name] = full_request.count(char)
        
        # 3. SQL keywords
        sql_keywords = [
            'select', 'union', 'insert', 'update', 'delete', 'drop', 'create', 'alter',
            'exec', 'execute', 'where', 'from', 'table', 'database', 'column',
            'or', 'and', '--', '/*', '*/', 'xp_', 'sp_', 'cast', 'char', 'varchar',
            'concat', 'declare', 'sys', 'information_schema'
        ]
        features['sql_keywords_count'] = sum(full_request.lower().count(kw) for kw in sql_keywords)
        
        # 4. XSS patterns
        xss_patterns = [
            '<script', '</script>', '<img', '<iframe', '<object', '<embed', '<svg',
            'onerror', 'onload', 'onclick', 'onmouseover', 'javascript:', 'vbscript:',
            'alert(', 'prompt(', 'confirm(', 'eval(', 'expression(', 'document.',
            'window.', 'cookie', 'localstorage'
        ]
        features['xss_patterns_count'] = sum(full_request.lower().count(pattern) for pattern in xss_patterns)
        
        # 5. Path traversal patterns
        features['path_traversal_count'] = full_request.count('..')
        features['slash_count'] = full_request.count('/')
        features['backslash_count'] = full_request.count('\\')
        
        # 6. URL structure features
        features['question_count'] = url.count('?')
        features['ampersand_count'] = url.count('&')
        features['equals_count'] = url.count('=')
        features['param_count'] = features['ampersand_count'] + features['question_count']
        
        # 7. Encoding detection
        features['encoded_chars_count'] = len(re.findall(r'%[0-9A-Fa-f]{2}', full_request))
        features['hex_count'] = len(re.findall(r'0x[0-9A-Fa-f]+', full_request))
        
        # 8. Character ratios
        total_len = len(full_request)
        if total_len > 0:
            features['uppercase_ratio'] = sum(1 for c in full_request if c.isupper()) / total_len
            features['digit_ratio'] = sum(1 for c in full_request if c.isdigit()) / total_len
            features['whitespace_ratio'] = sum(1 for c in full_request if c.isspace()) / total_len
            features['special_ratio'] = sum(1 for c in full_request if not c.isalnum() and not c.isspace()) / total_len
        else:
            features['uppercase_ratio'] = 0
            features['digit_ratio'] = 0
            features['whitespace_ratio'] = 0
            features['special_ratio'] = 0
        
        # 9. Entropy
        if total_len > 0:
            char_counts = Counter(full_request)
            probs = [count / total_len for count in char_counts.values()]
            features['entropy'] = scipy_entropy(probs, base=2)
        else:
            features['entropy'] = 0
        
        # 10. Binary flags
        features['has_quote'] = 1 if ("'" in full_request or '"' in full_request) else 0
        features['has_script_tag'] = 1 if '<script' in full_request.lower() else 0
        features['has_sql_comment'] = 1 if ('--' in full_request or '/*' in full_request) else 0
        features['has_union'] = 1 if 'union' in full_request.lower() else 0
        features['has_select'] = 1 if 'select' in full_request.lower() else 0
        features['has_insert'] = 1 if 'insert' in full_request.lower() else 0
        features['has_delete'] = 1 if 'delete' in full_request.lower() else 0
        features['has_drop'] = 1 if 'drop' in full_request.lower() else 0
        features['has_exec'] = 1 if 'exec' in full_request.lower() else 0
        features['has_alert'] = 1 if 'alert' in full_request.lower() else 0
        features['has_eval'] = 1 if 'eval' in full_request.lower() else 0
        
        return features
    
    def detect(self, url: str, content: str = "", method: str = "GET") -> Tuple[bool, Optional[str], float]:
        """
        Detect attacks using ML model
        
        Args:
            url: Request URL
            content: Request body/content
            method: HTTP method
            
        Returns:
            (is_attack, attack_type, confidence)
        """
        start_time = time.time()
        
        # Create DataFrame
        df = pd.DataFrame({
            'URL': [url],
            'content': [content],
            'Method': [method],
            'full_request': [f"{url} {content}"]
        })
        
        # Extract statistical features
        stat_features = self.extract_statistical_features(url, content, method)
        stat_df = pd.DataFrame([stat_features])
        
        # TF-IDF features
        tfidf_features = self.tfidf_vectorizer.transform(df['full_request'])
        
        # Method encoding
        method_features = self.method_encoder.transform(df[['Method']])
        
        # Combine all features
        stat_sparse = sparse.csr_matrix(stat_df.values)
        X = sparse.hstack([tfidf_features, stat_sparse, method_features])
        
        # Predict
        proba = self.model.predict_proba(X)[0]
        
        # Apply threshold
        is_attack = proba[1] >= self.threshold
        
        # Classify attack type based on features (heuristic)
        attack_type = None
        if is_attack:
            if stat_features['sql_keywords_count'] > 0 or stat_features['has_union'] or stat_features['has_select']:
                attack_type = "SQL Injection (ML)"
            elif stat_features['xss_patterns_count'] > 0 or stat_features['has_script_tag'] or stat_features['has_alert']:
                attack_type = "Cross-Site Scripting (ML)"
            elif stat_features['path_traversal_count'] > 0:
                attack_type = "Path Traversal (ML)"
            else:
                attack_type = "Suspicious Activity (ML)"
        
        confidence = proba[1]  # Probability of attack
        
        # Calculate processing time
        process_time = (time.time() - start_time) * 1000  # ms
        
        return is_attack, attack_type, confidence
    
    def get_stats(self) -> dict:
        """Get detector statistics"""
        return {
            "model_type": "Ensemble (XGBoost + LightGBM + RandomForest)",
            "threshold": self.threshold,
            "training_f1": self.metrics['f1_score'],
            "training_auc": self.metrics['auc_roc'],
            "tfidf_features": self.tfidf_vectorizer.max_features,
            "statistical_features": len(self.stat_feature_names),
            "total_features": self.tfidf_vectorizer.max_features + len(self.stat_feature_names) + 3
        }


if __name__ == "__main__":
    # Test
    detector = MLDetector()
    
    print("\n" + "=" * 80)
    print("🤖 ML DETECTOR - TEST")
    print("=" * 80)
    
    test_cases = [
        # Normal requests (should pass)
        ("/index.php?page=home", "", "Normal"),
        ("/search?q=hello", "", "Normal"),
        ("/api/users", '{"name":"John"}', "Normal"),
        
        # Sophisticated attacks (rules might miss)
        ("/login?user=admin'+OR+'1'='1", "", "SQLi"),
        ("/search?q=%27%20UNION%20SELECT%20*", "", "SQLi (encoded)"),
        ("/comment", "text=<svg/onload=alert(1)>", "XSS (obfuscated)"),
    ]
    
    print(f"\n📊 Testing {len(test_cases)} samples...\n")
    
    for url, content, expected in test_cases:
        is_attack, attack_type, confidence = detector.detect(url, content)
        
        pred_label = 'ATTACK' if is_attack else 'NORMAL'
        status = "✅" if (is_attack and "Normal" not in expected) or (not is_attack and "Normal" in expected) else "❌"
        
        print(f"{status} {expected:25} | {url[:45]:45}")
        print(f"   Predicted: {pred_label:6} | Confidence: {confidence:.4f} (threshold: {detector.threshold})")
        if attack_type:
            print(f"   Attack Type: {attack_type}")
        print()
    
    # Stats
    stats = detector.get_stats()
    print("=" * 80)
    print(f"📈 DETECTOR STATS:")
    for key, value in stats.items():
        print(f"   {key}: {value}")
    print("=" * 80)
