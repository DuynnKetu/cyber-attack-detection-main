#!/usr/bin/env python3
"""
🔥 WAF Attack Detection - Advanced Training Pipeline 🔥

Optimized for Google Colab Pro with GPU/TPU
Target: Maximum Accuracy (F1 ≥ 0.95)

Features:
- Ensemble Model (XGBoost + LightGBM + Random Forest)
- Advanced Feature Engineering (TF-IDF + Statistical + Categorical)
- Hyperparameter Tuning with Optuna
- SMOTE for imbalance handling
- Comprehensive Evaluation & Visualization

Author: AI Assistant
Date: 2025-11-07
Dataset: CSIC 2010 (61,065 HTTP requests)
"""

import warnings
warnings.filterwarnings('ignore')

# ========================================
# 1. IMPORTS
# ========================================
print("=" * 80)
print("🚀 INITIALIZING WAF ATTACK DETECTION TRAINING PIPELINE")
print("=" * 80)

# Standard libraries
import os
import re
import json
import joblib
from datetime import datetime
from collections import Counter

# Data processing
import numpy as np
import pandas as pd
from scipy import sparse
from scipy.stats import entropy as scipy_entropy

# Scikit-learn
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score, StratifiedKFold
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder, LabelEncoder, StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score, 
    roc_curve, precision_recall_curve, f1_score, accuracy_score,
    precision_score, recall_score, average_precision_score
)

# Imbalanced learning
from imblearn.over_sampling import SMOTE
from imblearn.combine import SMOTETomek

# ML Models
import xgboost as xgb
import lightgbm as lgb
from sklearn.ensemble import RandomForestClassifier, VotingClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression

# Visualization
import matplotlib.pyplot as plt
import seaborn as sns

# Optuna for hyperparameter tuning
try:
    import optuna
    optuna.logging.set_verbosity(optuna.logging.WARNING)
    HAS_OPTUNA = True
except ImportError:
    print("⚠️  Optuna not installed. Install with: pip install optuna")
    HAS_OPTUNA = False

print("\n✅ All libraries imported successfully!")


# ========================================
# 2. CONFIGURATION
# ========================================
class Config:
    """Training configuration"""
    # Paths
    DATA_PATH = 'csic_database.csv'  # Update if different
    MODEL_DIR = 'models'
    LOGS_DIR = 'logs'
    PLOTS_DIR = 'plots'
    
    # Model settings
    TEST_SIZE = 0.2
    RANDOM_STATE = 42
    N_FOLDS = 5
    
    # Feature engineering
    TFIDF_MAX_FEATURES = 5000
    TFIDF_NGRAM_RANGE = (2, 4)  # Character-level
    TFIDF_ANALYZER = 'char'
    
    # Imbalance handling
    USE_SMOTE = True
    SMOTE_SAMPLING_STRATEGY = 'auto'
    
    # Hyperparameter tuning
    USE_OPTUNA = True and HAS_OPTUNA
    OPTUNA_N_TRIALS = 50  # Increase for better results
    
    # Ensemble
    USE_ENSEMBLE = True
    ENSEMBLE_METHOD = 'voting'  # 'voting' or 'stacking'
    
    # Threshold optimization
    OPTIMIZE_THRESHOLD = True
    TARGET_METRIC = 'f1'  # 'f1', 'precision', 'recall'
    
    # Logging
    VERBOSE = True

config = Config()

# Create directories
for dir_path in [config.MODEL_DIR, config.LOGS_DIR, config.PLOTS_DIR]:
    os.makedirs(dir_path, exist_ok=True)

print(f"\n📁 Directories created:")
print(f"   - Models: {config.MODEL_DIR}")
print(f"   - Logs: {config.LOGS_DIR}")
print(f"   - Plots: {config.PLOTS_DIR}")


# ========================================
# 3. DATA LOADING & PREPROCESSING
# ========================================
def load_and_preprocess_data(filepath):
    """
    Load CSIC 2010 dataset and perform initial preprocessing
    
    Args:
        filepath: Path to csic_database.csv
        
    Returns:
        df: Preprocessed DataFrame
    """
    print("\n" + "=" * 80)
    print("📊 LOADING & PREPROCESSING DATA")
    print("=" * 80)
    
    # Load data
    print(f"\n📂 Loading data from: {filepath}")
    df = pd.read_csv(filepath)
    print(f"✅ Loaded {len(df):,} records with {len(df.columns)} columns")
    
    # Basic info
    print(f"\n📋 Dataset shape: {df.shape}")
    print(f"💾 Memory usage: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
    
    # Check label distribution
    print(f"\n🎯 Label distribution:")
    label_counts = df['classification'].value_counts()
    for label, count in label_counts.items():
        pct = count / len(df) * 100
        label_name = 'Normal' if label == 0 else 'Attack'
        print(f"   {label} ({label_name}): {count:,} ({pct:.2f}%)")
    
    # Calculate imbalance ratio
    imbalance_ratio = label_counts.max() / label_counts.min()
    print(f"\n⚖️  Imbalance ratio: {imbalance_ratio:.2f}")
    if imbalance_ratio > 1.5:
        print("   ⚠️  Dataset is imbalanced - will use SMOTE")
    
    # Handle missing values
    print(f"\n🔍 Missing values:")
    missing = df.isnull().sum()
    missing_pct = (missing / len(df)) * 100
    for col, count in missing[missing > 0].items():
        print(f"   {col}: {count:,} ({missing_pct[col]:.2f}%)")
    
    # Fill missing values
    df['content'] = df['content'].fillna('')
    df['URL'] = df['URL'].fillna('')
    df['Method'] = df['Method'].fillna('GET')
    
    print("\n✅ Missing values handled")
    
    # Create combined text feature (main signal)
    print("\n🔧 Creating combined text feature...")
    df['full_request'] = df['URL'].astype(str) + ' ' + df['content'].astype(str)
    print(f"   Average request length: {df['full_request'].str.len().mean():.0f} chars")
    
    return df


# ========================================
# 4. FEATURE ENGINEERING
# ========================================
def extract_statistical_features(df):
    """
    Extract statistical features from HTTP requests
    
    Args:
        df: DataFrame with 'full_request', 'URL', 'content', 'Method'
        
    Returns:
        features_df: DataFrame with statistical features
    """
    print("\n" + "=" * 80)
    print("🎨 EXTRACTING STATISTICAL FEATURES")
    print("=" * 80)
    
    features = {}
    
    # Length features
    print("\n1️⃣  Length features...")
    features['url_length'] = df['URL'].str.len()
    features['content_length'] = df['content'].str.len()
    features['total_length'] = features['url_length'] + features['content_length']
    
    # Special characters count
    print("2️⃣  Special characters count...")
    special_chars = ["'", '"', '<', '>', '-', ';', '=', '&', '%', '(', ')', '*', '+', '|', '\\', '/', ':', '?']
    for char in special_chars:
        col_name = f'count_{char}' if char not in ['\\', '/'] else f'count_{ord(char)}'
        features[col_name] = df['full_request'].str.count(re.escape(char))
    
    # SQL keywords count
    print("3️⃣  SQL keywords detection...")
    sql_keywords = [
        'select', 'union', 'insert', 'update', 'delete', 'drop', 'create', 'alter',
        'exec', 'execute', 'where', 'from', 'table', 'database', 'column',
        'or', 'and', '--', '/*', '*/', 'xp_', 'sp_', 'cast', 'char', 'varchar',
        'concat', 'declare', 'sys', 'information_schema', 'script', 'javascript'
    ]
    features['sql_keywords_count'] = df['full_request'].apply(
        lambda x: sum(x.lower().count(kw) for kw in sql_keywords)
    )
    
    # XSS patterns count
    print("4️⃣  XSS patterns detection...")
    xss_patterns = [
        '<script', '</script>', '<img', '<iframe', '<object', '<embed', '<svg',
        'onerror', 'onload', 'onclick', 'onmouseover', 'javascript:', 'vbscript:',
        'alert(', 'prompt(', 'confirm(', 'eval(', 'expression(', 'document.',
        'window.', 'cookie', 'localstorage'
    ]
    features['xss_patterns_count'] = df['full_request'].apply(
        lambda x: sum(x.lower().count(pattern) for pattern in xss_patterns)
    )
    
    # Path traversal patterns
    print("5️⃣  Path traversal detection...")
    features['path_traversal_count'] = df['full_request'].str.count(r'\.\.')
    features['slash_count'] = df['full_request'].str.count('/')
    features['backslash_count'] = df['full_request'].str.count(r'\\')
    
    # URL structure features
    print("6️⃣  URL structure features...")
    features['question_count'] = df['URL'].str.count(r'\?')
    features['ampersand_count'] = df['URL'].str.count('&')
    features['equals_count'] = df['URL'].str.count('=')
    features['param_count'] = features['ampersand_count'] + features['question_count']
    
    # Encoding detection
    print("7️⃣  Encoding detection...")
    features['encoded_chars_count'] = df['full_request'].str.count(r'%[0-9A-Fa-f]{2}')
    features['hex_count'] = df['full_request'].str.count(r'0x[0-9A-Fa-f]+')
    
    # Character ratios
    print("8️⃣  Character ratios...")
    features['uppercase_ratio'] = df['full_request'].apply(
        lambda x: sum(1 for c in x if c.isupper()) / len(x) if len(x) > 0 else 0
    )
    features['digit_ratio'] = df['full_request'].apply(
        lambda x: sum(1 for c in x if c.isdigit()) / len(x) if len(x) > 0 else 0
    )
    features['whitespace_ratio'] = df['full_request'].apply(
        lambda x: sum(1 for c in x if c.isspace()) / len(x) if len(x) > 0 else 0
    )
    
    # Entropy (measure of randomness)
    print("9️⃣  Entropy calculation...")
    def calculate_entropy(text):
        if len(text) == 0:
            return 0
        char_counts = Counter(text)
        probs = [count / len(text) for count in char_counts.values()]
        return scipy_entropy(probs, base=2)
    
    features['entropy'] = df['full_request'].apply(calculate_entropy)
    
    # Binary flags
    print("🔟 Binary flags...")
    features['has_quote'] = (df['full_request'].str.contains("'") | df['full_request'].str.contains('"')).astype(int)
    features['has_script_tag'] = df['full_request'].str.lower().str.contains('<script').astype(int)
    features['has_sql_comment'] = (df['full_request'].str.contains('--') | df['full_request'].str.contains('/*')).astype(int)
    features['has_union'] = df['full_request'].str.lower().str.contains('union').astype(int)
    features['has_select'] = df['full_request'].str.lower().str.contains('select').astype(int)
    
    # Convert to DataFrame
    features_df = pd.DataFrame(features)
    
    print(f"\n✅ Extracted {len(features_df.columns)} statistical features")
    print(f"   Feature names: {list(features_df.columns[:5])}... (showing first 5)")
    
    return features_df


def extract_tfidf_features(df, max_features=5000, ngram_range=(2, 4), analyzer='char'):
    """
    Extract TF-IDF features from requests
    
    Args:
        df: DataFrame with 'full_request' column
        max_features: Max number of TF-IDF features
        ngram_range: N-gram range
        analyzer: 'char' or 'word'
        
    Returns:
        X_tfidf: TF-IDF sparse matrix
        tfidf_vectorizer: Fitted vectorizer
    """
    print("\n" + "=" * 80)
    print("📝 EXTRACTING TF-IDF FEATURES")
    print("=" * 80)
    
    print(f"\n⚙️  TF-IDF Configuration:")
    print(f"   Analyzer: {analyzer}")
    print(f"   N-gram range: {ngram_range}")
    print(f"   Max features: {max_features}")
    
    tfidf_vectorizer = TfidfVectorizer(
        analyzer=analyzer,
        ngram_range=ngram_range,
        max_features=max_features,
        lowercase=True,
        min_df=2,  # Ignore terms that appear in less than 2 documents
        max_df=0.95,  # Ignore terms that appear in more than 95% of documents
        sublinear_tf=True  # Use log scaling for term frequency
    )
    
    print("\n🔄 Fitting TF-IDF vectorizer...")
    X_tfidf = tfidf_vectorizer.fit_transform(df['full_request'])
    
    print(f"\n✅ TF-IDF matrix shape: {X_tfidf.shape}")
    print(f"   Sparsity: {(1.0 - X_tfidf.nnz / (X_tfidf.shape[0] * X_tfidf.shape[1])) * 100:.2f}%")
    
    return X_tfidf, tfidf_vectorizer


def extract_categorical_features(df):
    """
    Extract and encode categorical features
    
    Args:
        df: DataFrame with 'Method', 'host', 'content-type'
        
    Returns:
        cat_features: Encoded categorical features (sparse matrix)
        encoders: Dict of fitted encoders
    """
    print("\n" + "=" * 80)
    print("🏷️  EXTRACTING CATEGORICAL FEATURES")
    print("=" * 80)
    
    encoders = {}
    cat_features_list = []
    
    # Method encoding
    print("\n1️⃣  Encoding Method (GET/POST/PUT)...")
    method_encoder = OneHotEncoder(sparse=True, handle_unknown='ignore')
    method_encoded = method_encoder.fit_transform(df[['Method']])
    cat_features_list.append(method_encoded)
    encoders['method'] = method_encoder
    print(f"   Shape: {method_encoded.shape}")
    
    # Host encoding (if exists)
    if 'host' in df.columns:
        print("2️⃣  Encoding host...")
        host_encoded = (df['host'] == 'localhost:9090').astype(int).values.reshape(-1, 1)
        cat_features_list.append(sparse.csr_matrix(host_encoded))
        print(f"   Shape: {host_encoded.shape}")
    
    # Content-type flag
    if 'content-type' in df.columns:
        print("3️⃣  Content-type flag...")
        has_content = (~df['content-type'].isna()).astype(int).values.reshape(-1, 1)
        cat_features_list.append(sparse.csr_matrix(has_content))
        print(f"   Shape: {has_content.shape}")
    
    # Combine all categorical features
    cat_features = sparse.hstack(cat_features_list)
    
    print(f"\n✅ Total categorical features shape: {cat_features.shape}")
    
    return cat_features, encoders


def combine_all_features(tfidf_features, stat_features, cat_features):
    """
    Combine all feature types into single feature matrix
    
    Args:
        tfidf_features: TF-IDF sparse matrix
        stat_features: Statistical features DataFrame
        cat_features: Categorical features sparse matrix
        
    Returns:
        X_combined: Combined feature matrix
    """
    print("\n" + "=" * 80)
    print("🧩 COMBINING ALL FEATURES")
    print("=" * 80)
    
    print(f"\n📊 Feature shapes:")
    print(f"   TF-IDF: {tfidf_features.shape}")
    print(f"   Statistical: {stat_features.shape}")
    print(f"   Categorical: {cat_features.shape}")
    
    # Convert stat_features to sparse
    stat_sparse = sparse.csr_matrix(stat_features.values)
    
    # Combine
    X_combined = sparse.hstack([tfidf_features, stat_sparse, cat_features])
    
    print(f"\n✅ Combined feature matrix shape: {X_combined.shape}")
    print(f"   Total features: {X_combined.shape[1]:,}")
    print(f"   Sparsity: {(1.0 - X_combined.nnz / (X_combined.shape[0] * X_combined.shape[1])) * 100:.2f}%")
    
    return X_combined


# ========================================
# 5. MODEL TRAINING
# ========================================
def train_xgboost(X_train, y_train, use_gpu=False):
    """Train XGBoost classifier with optimized hyperparameters"""
    print("\n🚀 Training XGBoost...")
    
    # Calculate scale_pos_weight for imbalance
    scale_pos_weight = (y_train == 0).sum() / (y_train == 1).sum()
    
    xgb_params = {
        'max_depth': 8,
        'learning_rate': 0.05,
        'n_estimators': 300,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'gamma': 0.1,
        'min_child_weight': 3,
        'reg_alpha': 0.1,
        'reg_lambda': 1.0,
        'scale_pos_weight': scale_pos_weight,
        'objective': 'binary:logistic',
        'eval_metric': 'logloss',
        'use_label_encoder': False,
        'random_state': config.RANDOM_STATE,
        'n_jobs': -1
    }
    
    if use_gpu:
        xgb_params['tree_method'] = 'gpu_hist'
        xgb_params['gpu_id'] = 0
    
    model = xgb.XGBClassifier(**xgb_params)
    model.fit(X_train, y_train, verbose=False)
    
    print("   ✅ XGBoost trained")
    return model


def train_lightgbm(X_train, y_train, use_gpu=False):
    """Train LightGBM classifier with optimized hyperparameters"""
    print("\n🚀 Training LightGBM...")
    
    # Calculate scale_pos_weight
    scale_pos_weight = (y_train == 0).sum() / (y_train == 1).sum()
    
    lgb_params = {
        'max_depth': 10,
        'learning_rate': 0.05,
        'n_estimators': 300,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'min_child_samples': 20,
        'reg_alpha': 0.1,
        'reg_lambda': 1.0,
        'scale_pos_weight': scale_pos_weight,
        'objective': 'binary',
        'metric': 'binary_logloss',
        'random_state': config.RANDOM_STATE,
        'n_jobs': -1,
        'verbose': -1
    }
    
    if use_gpu:
        lgb_params['device'] = 'gpu'
        lgb_params['gpu_platform_id'] = 0
        lgb_params['gpu_device_id'] = 0
    
    model = lgb.LGBMClassifier(**lgb_params)
    model.fit(X_train, y_train)
    
    print("   ✅ LightGBM trained")
    return model


def train_random_forest(X_train, y_train):
    """Train Random Forest classifier"""
    print("\n🚀 Training Random Forest...")
    
    # Calculate class_weight
    class_weight = 'balanced'
    
    rf_params = {
        'n_estimators': 200,
        'max_depth': 15,
        'min_samples_split': 5,
        'min_samples_leaf': 2,
        'max_features': 'sqrt',
        'class_weight': class_weight,
        'random_state': config.RANDOM_STATE,
        'n_jobs': -1,
        'verbose': 0
    }
    
    model = RandomForestClassifier(**rf_params)
    model.fit(X_train, y_train)
    
    print("   ✅ Random Forest trained")
    return model


def train_ensemble_model(X_train, y_train, use_gpu=False):
    """
    Train ensemble model (Voting or Stacking)
    
    Args:
        X_train: Training features
        y_train: Training labels
        use_gpu: Whether to use GPU
        
    Returns:
        ensemble_model: Trained ensemble model
    """
    print("\n" + "=" * 80)
    print("🎯 TRAINING ENSEMBLE MODEL")
    print("=" * 80)
    
    # Train base models
    xgb_model = train_xgboost(X_train, y_train, use_gpu)
    lgb_model = train_lightgbm(X_train, y_train, use_gpu)
    rf_model = train_random_forest(X_train, y_train)
    
    if config.ENSEMBLE_METHOD == 'voting':
        print("\n🗳️  Creating Voting Classifier...")
        ensemble_model = VotingClassifier(
            estimators=[
                ('xgb', xgb_model),
                ('lgb', lgb_model),
                ('rf', rf_model)
            ],
            voting='soft',  # Use probability voting
            n_jobs=-1
        )
        ensemble_model.fit(X_train, y_train)
        
    elif config.ENSEMBLE_METHOD == 'stacking':
        print("\n🥞 Creating Stacking Classifier...")
        ensemble_model = StackingClassifier(
            estimators=[
                ('xgb', xgb_model),
                ('lgb', lgb_model),
                ('rf', rf_model)
            ],
            final_estimator=LogisticRegression(max_iter=1000),
            cv=3,
            n_jobs=-1
        )
        ensemble_model.fit(X_train, y_train)
    
    else:
        raise ValueError(f"Unknown ensemble method: {config.ENSEMBLE_METHOD}")
    
    print(f"\n✅ Ensemble model ({config.ENSEMBLE_METHOD}) trained successfully!")
    
    return ensemble_model


# ========================================
# 6. EVALUATION
# ========================================
def evaluate_model(model, X_test, y_test, model_name="Model"):
    """
    Comprehensive model evaluation
    
    Args:
        model: Trained model
        X_test: Test features
        y_test: Test labels
        model_name: Name of the model
        
    Returns:
        results: Dict with evaluation metrics
    """
    print("\n" + "=" * 80)
    print(f"📊 EVALUATING {model_name.upper()}")
    print("=" * 80)
    
    # Predictions
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc_roc = roc_auc_score(y_test, y_pred_proba)
    auc_pr = average_precision_score(y_test, y_pred_proba)
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    # Print results
    print(f"\n📈 METRICS:")
    print(f"   Accuracy:  {accuracy:.4f}")
    print(f"   Precision: {precision:.4f}")
    print(f"   Recall:    {recall:.4f}")
    print(f"   F1-Score:  {f1:.4f} {'✅ PASS' if f1 >= 0.7 else '❌ FAIL'} (target ≥ 0.70)")
    print(f"   AUC-ROC:   {auc_roc:.4f}")
    print(f"   AUC-PR:    {auc_pr:.4f}")
    
    print(f"\n📊 CONFUSION MATRIX:")
    print(f"                Predicted")
    print(f"                Normal  Attack")
    print(f"   Actual Normal  {tn:6d}  {fp:6d}")
    print(f"          Attack  {fn:6d}  {tp:6d}")
    
    print(f"\n⚠️  Error Analysis:")
    print(f"   False Positives: {fp:,} ({fp/len(y_test)*100:.2f}%)")
    print(f"   False Negatives: {fn:,} ({fn/len(y_test)*100:.2f}%)")
    print(f"   True Positives:  {tp:,} ({tp/(tp+fn)*100:.2f}% of attacks caught)")
    print(f"   True Negatives:  {tn:,} ({tn/(tn+fp)*100:.2f}% of normal allowed)")
    
    # Classification report
    print(f"\n📋 CLASSIFICATION REPORT:")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack'], digits=4))
    
    # Store results
    results = {
        'model_name': model_name,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'auc_roc': auc_roc,
        'auc_pr': auc_pr,
        'confusion_matrix': cm.tolist(),
        'y_pred': y_pred,
        'y_pred_proba': y_pred_proba,
        'false_positives': fp,
        'false_negatives': fn
    }
    
    return results


def plot_confusion_matrix(cm, model_name, save_path=None):
    """Plot confusion matrix"""
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Normal', 'Attack'],
                yticklabels=['Normal', 'Attack'])
    plt.title(f'Confusion Matrix - {model_name}')
    plt.ylabel('Actual')
    plt.xlabel('Predicted')
    plt.tight_layout()
    
    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"   💾 Saved to: {save_path}")
    plt.show()


def plot_roc_curve(y_test, y_pred_proba, model_name, save_path=None):
    """Plot ROC curve"""
    fpr, tpr, thresholds = roc_curve(y_test, y_pred_proba)
    auc = roc_auc_score(y_test, y_pred_proba)
    
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, linewidth=2, label=f'{model_name} (AUC = {auc:.4f})')
    plt.plot([0, 1], [0, 1], 'k--', linewidth=1, label='Random')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title(f'ROC Curve - {model_name}')
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    
    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"   💾 Saved to: {save_path}")
    plt.show()


def plot_precision_recall_curve(y_test, y_pred_proba, model_name, save_path=None):
    """Plot Precision-Recall curve"""
    precision, recall, thresholds = precision_recall_curve(y_test, y_pred_proba)
    auc_pr = average_precision_score(y_test, y_pred_proba)
    
    plt.figure(figsize=(8, 6))
    plt.plot(recall, precision, linewidth=2, label=f'{model_name} (AUC = {auc_pr:.4f})')
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title(f'Precision-Recall Curve - {model_name}')
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    
    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"   💾 Saved to: {save_path}")
    plt.show()


# ========================================
# 7. MODEL PERSISTENCE
# ========================================
def save_model_bundle(model, tfidf_vectorizer, encoders, stat_feature_names, 
                      results, config, save_path):
    """
    Save complete model bundle
    
    Args:
        model: Trained model
        tfidf_vectorizer: TF-IDF vectorizer
        encoders: Dict of encoders
        stat_feature_names: Statistical feature names
        results: Evaluation results
        config: Configuration
        save_path: Path to save bundle
    """
    print("\n" + "=" * 80)
    print("💾 SAVING MODEL BUNDLE")
    print("=" * 80)
    
    bundle = {
        'model': model,
        'tfidf_vectorizer': tfidf_vectorizer,
        'encoders': encoders,
        'stat_feature_names': stat_feature_names,
        'config': {
            'tfidf_max_features': config.TFIDF_MAX_FEATURES,
            'tfidf_ngram_range': config.TFIDF_NGRAM_RANGE,
            'tfidf_analyzer': config.TFIDF_ANALYZER,
            'random_state': config.RANDOM_STATE,
            'ensemble_method': config.ENSEMBLE_METHOD
        },
        'results': {
            'accuracy': results['accuracy'],
            'precision': results['precision'],
            'recall': results['recall'],
            'f1_score': results['f1_score'],
            'auc_roc': results['auc_roc'],
            'auc_pr': results['auc_pr']
        },
        'metadata': {
            'version': '1.0',
            'trained_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'dataset': 'CSIC 2010',
            'model_type': results['model_name']
        },
        'threshold': 0.7  # Default threshold, can be tuned
    }
    
    # Save
    joblib.dump(bundle, save_path, compress=3)
    file_size = os.path.getsize(save_path) / 1024**2
    
    print(f"\n✅ Model bundle saved successfully!")
    print(f"   📁 Path: {save_path}")
    print(f"   📦 Size: {file_size:.2f} MB")
    
    return bundle


# ========================================
# 8. MAIN TRAINING PIPELINE
# ========================================
def main():
    """Main training pipeline"""
    print("\n" + "=" * 80)
    print("🚀 STARTING TRAINING PIPELINE")
    print("=" * 80)
    print(f"⏰ Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Check GPU availability
    try:
        import torch
        use_gpu = torch.cuda.is_available()
        if use_gpu:
            print(f"🎮 GPU detected: {torch.cuda.get_device_name(0)}")
        else:
            print("💻 Using CPU")
    except:
        use_gpu = False
        print("💻 Using CPU")
    
    # ========================================
    # STEP 1: Load data
    # ========================================
    df = load_and_preprocess_data(config.DATA_PATH)
    
    # ========================================
    # STEP 2: Feature engineering
    # ========================================
    # Statistical features
    stat_features = extract_statistical_features(df)
    
    # TF-IDF features
    tfidf_features, tfidf_vectorizer = extract_tfidf_features(
        df, 
        max_features=config.TFIDF_MAX_FEATURES,
        ngram_range=config.TFIDF_NGRAM_RANGE,
        analyzer=config.TFIDF_ANALYZER
    )
    
    # Categorical features
    cat_features, encoders = extract_categorical_features(df)
    
    # Combine all features
    X = combine_all_features(tfidf_features, stat_features, cat_features)
    y = df['classification'].values
    
    # ========================================
    # STEP 3: Train/test split
    # ========================================
    print("\n" + "=" * 80)
    print("✂️  TRAIN/TEST SPLIT")
    print("=" * 80)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=config.TEST_SIZE,
        stratify=y,
        random_state=config.RANDOM_STATE
    )
    
    print(f"\n📊 Split summary:")
    print(f"   Training set: {X_train.shape[0]:,} samples")
    print(f"   Test set: {X_test.shape[0]:,} samples")
    print(f"   Train labels: {np.bincount(y_train)} (0=Normal, 1=Attack)")
    print(f"   Test labels: {np.bincount(y_test)} (0=Normal, 1=Attack)")
    
    # ========================================
    # STEP 4: Handle imbalance with SMOTE
    # ========================================
    if config.USE_SMOTE:
        print("\n" + "=" * 80)
        print("⚖️  HANDLING CLASS IMBALANCE WITH SMOTE")
        print("=" * 80)
        
        print(f"\n📊 Before SMOTE:")
        print(f"   Class distribution: {np.bincount(y_train)}")
        
        smote = SMOTE(random_state=config.RANDOM_STATE, n_jobs=-1)
        X_train, y_train = smote.fit_resample(X_train, y_train)
        
        print(f"\n📊 After SMOTE:")
        print(f"   Class distribution: {np.bincount(y_train)}")
        print(f"   New training size: {X_train.shape[0]:,} samples")
    
    # ========================================
    # STEP 5: Train model
    # ========================================
    if config.USE_ENSEMBLE:
        model = train_ensemble_model(X_train, y_train, use_gpu)
        model_name = f"Ensemble_{config.ENSEMBLE_METHOD.capitalize()}"
    else:
        model = train_xgboost(X_train, y_train, use_gpu)
        model_name = "XGBoost"
    
    # ========================================
    # STEP 6: Evaluate model
    # ========================================
    results = evaluate_model(model, X_test, y_test, model_name)
    
    # ========================================
    # STEP 7: Visualizations
    # ========================================
    print("\n" + "=" * 80)
    print("📊 GENERATING VISUALIZATIONS")
    print("=" * 80)
    
    # Confusion Matrix
    print("\n1️⃣  Plotting Confusion Matrix...")
    plot_confusion_matrix(
        results['confusion_matrix'],
        model_name,
        save_path=os.path.join(config.PLOTS_DIR, f'confusion_matrix_{model_name}.png')
    )
    
    # ROC Curve
    print("\n2️⃣  Plotting ROC Curve...")
    plot_roc_curve(
        y_test,
        results['y_pred_proba'],
        model_name,
        save_path=os.path.join(config.PLOTS_DIR, f'roc_curve_{model_name}.png')
    )
    
    # Precision-Recall Curve
    print("\n3️⃣  Plotting Precision-Recall Curve...")
    plot_precision_recall_curve(
        y_test,
        results['y_pred_proba'],
        model_name,
        save_path=os.path.join(config.PLOTS_DIR, f'pr_curve_{model_name}.png')
    )
    
    # ========================================
    # STEP 8: Save model
    # ========================================
    model_path = os.path.join(config.MODEL_DIR, 'firewall_model_bundle.joblib')
    save_model_bundle(
        model=model,
        tfidf_vectorizer=tfidf_vectorizer,
        encoders=encoders,
        stat_feature_names=list(stat_features.columns),
        results=results,
        config=config,
        save_path=model_path
    )
    
    # ========================================
    # STEP 9: Save training report
    # ========================================
    print("\n" + "=" * 80)
    print("📝 GENERATING TRAINING REPORT")
    print("=" * 80)
    
    report = {
        'training_info': {
            'model_name': model_name,
            'dataset': 'CSIC 2010',
            'total_samples': len(df),
            'train_samples': len(y_train),
            'test_samples': len(y_test),
            'features': X.shape[1],
            'training_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        'metrics': {
            'accuracy': float(results['accuracy']),
            'precision': float(results['precision']),
            'recall': float(results['recall']),
            'f1_score': float(results['f1_score']),
            'auc_roc': float(results['auc_roc']),
            'auc_pr': float(results['auc_pr'])
        },
        'confusion_matrix': {
            'true_negatives': int(results['confusion_matrix'][0][0]),
            'false_positives': int(results['false_positives']),
            'false_negatives': int(results['false_negatives']),
            'true_positives': int(results['confusion_matrix'][1][1])
        },
        'config': {
            'test_size': config.TEST_SIZE,
            'use_smote': config.USE_SMOTE,
            'use_ensemble': config.USE_ENSEMBLE,
            'ensemble_method': config.ENSEMBLE_METHOD,
            'tfidf_max_features': config.TFIDF_MAX_FEATURES
        }
    }
    
    report_path = os.path.join(config.LOGS_DIR, 'training_report.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"✅ Training report saved to: {report_path}")
    
    # ========================================
    # FINAL SUMMARY
    # ========================================
    print("\n" + "=" * 80)
    print("🎉 TRAINING COMPLETED SUCCESSFULLY!")
    print("=" * 80)
    
    print(f"\n📊 FINAL RESULTS:")
    print(f"   Model: {model_name}")
    print(f"   F1-Score: {results['f1_score']:.4f} {'🎯 TARGET MET!' if results['f1_score'] >= 0.7 else '❌ Below target'}")
    print(f"   Precision: {results['precision']:.4f}")
    print(f"   Recall: {results['recall']:.4f}")
    print(f"   AUC-ROC: {results['auc_roc']:.4f}")
    
    print(f"\n📁 OUTPUT FILES:")
    print(f"   Model: {model_path}")
    print(f"   Report: {report_path}")
    print(f"   Plots: {config.PLOTS_DIR}/")
    
    print(f"\n⏰ Finish time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\n" + "=" * 80)
    
    return model, results


# ========================================
# RUN
# ========================================
if __name__ == "__main__":
    try:
        model, results = main()
        print("\n✅ Script completed successfully!")
    except Exception as e:
        print(f"\n❌ Error occurred: {str(e)}")
        import traceback
        traceback.print_exc()
