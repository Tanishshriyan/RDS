"""
Universal LightGBM Ransomware Detection Model Trainer
Handles ANY dataset format automatically - VirusTotal, ANY.RUN, Kaggle, custom datasets
No manual configuration needed!
"""
import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')

# ML imports
import lightgbm as lgb
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, roc_curve
)

# ===========================================================================
# CONFIGURATION
# ===========================================================================
class Config:
    # Paths
    PROJECT_ROOT = Path(__file__).parent.parent
    DATASET_DIR = PROJECT_ROOT / "data" / "training_data"
    MODEL_DIR = PROJECT_ROOT / "ml_model" / "models"
    LOGS_DIR = PROJECT_ROOT / "ml_model" / "logs"
    
    # Model parameters
    MODEL_VERSION = "2.0"
    TEST_SIZE = 0.2
    RANDOM_STATE = 42
    CROSS_VAL_FOLDS = 5
    
    # LightGBM hyperparameters (optimized for ransomware detection)
    LGBM_PARAMS = {
        'objective': 'binary',
        'metric': 'binary_logloss',
        'boosting_type': 'gbdt',
        'num_leaves': 31,
        'learning_rate': 0.05,
        'feature_fraction': 0.9,
        'bagging_fraction': 0.8,
        'bagging_freq': 5,
        'max_depth': -1,
        'min_child_samples': 20,
        'reg_alpha': 0.1,
        'reg_lambda': 0.1,
        'n_estimators': 500,
        'early_stopping_rounds': 50,
        'verbose': -1,
        'random_state': RANDOM_STATE,
        'n_jobs': -1,
        'class_weight': 'balanced'  # Handle imbalanced datasets
    }
    
    # Expected feature names (your 22 features)
    FEATURE_COLUMNS = [
        "cpu_percent", "memory_percent", "threads", "uptime", "cpu_spike_count",
        "file_writes", "file_reads", "file_deletes", "file_renames", "file_modifications",
        "extension_changes", "entropy_mean", "entropy_variance", "entropy_max",
        "high_entropy_file_ratio", "rapid_file_ops_count", "mass_file_change_events",
        "suspicious_extensions_count", "network_connections", "outbound_data_kb",
        "read_write_delete_pattern", "process_injection_attempts"
    ]
    
    # Possible label column names from various sources
    LABEL_COLUMN_NAMES = [
        'malware_label', 'label', 'target', 'class', 'classification', 'y',
        'is_malicious', 'is_ransomware', 'is_malware', 'malware', 'ransomware',
        'verdict', 'behavior_class', 'threat_type', 'category', 'result',
        'detection', 'status', 'type', 'outcome'
    ]
    
    # Terms indicating benign/safe samples
    BENIGN_TERMS = [
        'benign', 'clean', 'safe', 'normal', 'legitimate', 'trusted',
        'goodware', 'whitelist', '0', 'false', 'no', 'negative', 'ok'
    ]
    
    # Terms indicating malicious/ransomware samples
    MALICIOUS_TERMS = [
        'malware', 'ransomware', 'malicious', 'threat', 'dangerous',
        'infected', 'suspicious', 'positive', '1', 'true', 'yes', 'bad'
    ]

# ===========================================================================
# UTILITY FUNCTIONS
# ===========================================================================

def setup_directories():
    """Create necessary directories"""
    Config.DATASET_DIR.mkdir(parents=True, exist_ok=True)
    Config.MODEL_DIR.mkdir(parents=True, exist_ok=True)
    Config.LOGS_DIR.mkdir(parents=True, exist_ok=True)

def find_latest_dataset() -> Optional[Path]:
    """Find the most recent dataset in the datasets directory"""
    if not Config.DATASET_DIR.exists():
        return None
    
    csv_files = list(Config.DATASET_DIR.glob("*.csv"))
    if not csv_files:
        return None
    
    # Sort by modification time, return most recent
    latest = max(csv_files, key=lambda p: p.stat().st_mtime)
    return latest

def detect_label_column(df: pd.DataFrame) -> str:
    """Automatically detect which column contains the labels"""
    for col_name in Config.LABEL_COLUMN_NAMES:
        if col_name in df.columns:
            return col_name
    
    # If not found, look for any column with binary-like values
    for col in df.columns:
        unique_vals = df[col].unique()
        if len(unique_vals) <= 10:  # Likely a categorical column
            if set(unique_vals).issubset({0, 1, '0', '1', True, False}):
                return col
            # Check for text labels
            str_vals = [str(v).lower() for v in unique_vals]
            if any(term in ' '.join(str_vals) for term in Config.BENIGN_TERMS + Config.MALICIOUS_TERMS):
                return col
    
    raise ValueError(
        f"❌ Could not detect label column!\n"
        f"Available columns: {list(df.columns)}\n"
        f"Expected one of: {Config.LABEL_COLUMN_NAMES}\n"
        f"Or a binary column with values like 0/1, benign/malware, etc."
    )

def standardize_labels(df: pd.DataFrame, label_col: str) -> pd.DataFrame:
    """Convert any label format to binary 0/1 and rename to 'malware_label'"""
    print(f"   🔄 Processing label column: '{label_col}'")
    
    # Get unique values
    unique_vals = df[label_col].unique()
    print(f"   📊 Found label values: {unique_vals}")
    
    # Function to convert to binary
    def to_binary(val):
        if pd.isna(val):
            return 0  # Treat NaN as benign
        
        val_str = str(val).lower().strip()
        
        # Check if already binary
        if val in [0, 1] or val_str in ['0', '1']:
            return int(val)
        
        # Check benign terms
        if any(term in val_str for term in Config.BENIGN_TERMS):
            return 0
        
        # Check malicious terms
        if any(term in val_str for term in Config.MALICIOUS_TERMS):
            return 1
        
        # Default: unknown values treated as benign (safer for production)
        print(f"   ⚠️  Unknown label value '{val}' - treating as benign")
        return 0
    
    # Apply conversion
    df['malware_label'] = df[label_col].apply(to_binary)
    
    # Drop original label column if different
    if label_col != 'malware_label':
        df = df.drop(columns=[label_col])
    
    # Verify conversion
    final_vals = df['malware_label'].unique()
    benign_count = (df['malware_label'] == 0).sum()
    malicious_count = (df['malware_label'] == 1).sum()
    
    print(f"   ✅ Standardized to binary labels: {final_vals}")
    print(f"   📊 Benign: {benign_count:,} ({benign_count/len(df)*100:.1f}%)")
    print(f"   📊 Malicious: {malicious_count:,} ({malicious_count/len(df)*100:.1f}%)")
    
    if benign_count == 0:
        raise ValueError("❌ No benign samples found! Check label conversion logic.")
    if malicious_count == 0:
        raise ValueError("❌ No malicious samples found! Check label conversion logic.")
    
    return df

def map_feature_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Intelligently map dataset columns to expected feature names
    Handles different naming conventions from various data sources
    """
    print(f"\n   🔧 Mapping feature columns...")
    
    # Common alternative names for each feature
    feature_mappings = {
        'cpu_percent': ['cpu', 'cpu_usage', 'cpu_util', 'processor_percent', 'cpu_load'],
        'memory_percent': ['memory', 'mem', 'ram', 'memory_usage', 'mem_percent', 'ram_percent'],
        'threads': ['thread_count', 'num_threads', 'thread', 'threads_count'],
        'uptime': ['runtime', 'elapsed_time', 'duration', 'execution_time'],
        'file_writes': ['writes', 'write_count', 'file_write', 'write_ops', 'files_written'],
        'file_reads': ['reads', 'read_count', 'file_read', 'read_ops', 'files_read'],
        'file_deletes': ['deletes', 'delete_count', 'file_delete', 'deleted_files'],
        'file_renames': ['renames', 'rename_count', 'file_rename', 'renamed_files'],
        'file_modifications': ['modifications', 'modified', 'file_modified', 'mod_count'],
        'extension_changes': ['ext_changes', 'extension_change', 'ext_modified'],
        'entropy_mean': ['entropy', 'avg_entropy', 'mean_entropy', 'entropy_average'],
        'entropy_variance': ['entropy_var', 'entropy_std', 'entropy_deviation'],
        'entropy_max': ['max_entropy', 'entropy_maximum', 'peak_entropy'],
        'network_connections': ['connections', 'net_connections', 'network', 'conn_count'],
        'outbound_data_kb': ['outbound_data', 'data_sent', 'upload_kb', 'bytes_sent'],
    }
    
    renamed = {}
    for expected_name, alternatives in feature_mappings.items():
        if expected_name in df.columns:
            continue  # Already has correct name
        
        # Check alternatives
        for alt_name in alternatives:
            if alt_name in df.columns:
                df = df.rename(columns={alt_name: expected_name})
                renamed[alt_name] = expected_name
                break
    
    if renamed:
        print(f"   ✅ Renamed {len(renamed)} columns:")
        for old, new in renamed.items():
            print(f"      '{old}' → '{new}'")
    
    return df

def fill_missing_features(df: pd.DataFrame) -> pd.DataFrame:
    """Fill missing features with safe default values"""
    missing = set(Config.FEATURE_COLUMNS) - set(df.columns)
    
    if missing:
        print(f"\n   ⚠️  Missing {len(missing)} features - filling with defaults:")
        
        for feature in missing:
            if 'entropy' in feature:
                default = 5.0  # Low entropy (normal files)
            elif 'percent' in feature:
                default = 10.0  # Low resource usage
            elif 'ratio' in feature:
                default = 0.0
            elif 'count' in feature or 'events' in feature or 'attempts' in feature:
                default = 0
            elif feature == 'threads':
                default = 4
            elif feature == 'uptime':
                default = 300
            else:
                default = 0
            
            df[feature] = default
            print(f"      '{feature}' = {default}")
    
    return df

def handle_infinite_and_nan(df: pd.DataFrame) -> pd.DataFrame:
    """Replace infinite and NaN values"""
    # Replace infinity
    df = df.replace([np.inf, -np.inf], np.nan)
    
    # Count NaNs before filling
    nan_counts = df[Config.FEATURE_COLUMNS].isna().sum()
    total_nans = nan_counts.sum()
    
    if total_nans > 0:
        print(f"\n   🔧 Handling {total_nans} missing values...")
        
        # Fill numeric columns with median
        for col in Config.FEATURE_COLUMNS:
            if df[col].isna().any():
                median_val = df[col].median()
                df[col] = df[col].fillna(median_val)
                print(f"      '{col}': filled with median ({median_val:.2f})")
    
    return df

def remove_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    """Remove duplicate rows"""
    before = len(df)
    df = df.drop_duplicates(subset=Config.FEATURE_COLUMNS)
    after = len(df)
    
    if before > after:
        print(f"   🗑️  Removed {before - after:,} duplicate samples")
    
    return df

def balance_dataset(df: pd.DataFrame, max_ratio: float = 10.0) -> pd.DataFrame:
    """
    Balance extremely imbalanced datasets
    If ratio > max_ratio, undersample majority class
    """
    benign_count = (df['malware_label'] == 0).sum()
    malicious_count = (df['malware_label'] == 1).sum()
    ratio = max(benign_count, malicious_count) / min(benign_count, malicious_count)
    
    if ratio > max_ratio:
        print(f"\n   ⚖️  Dataset highly imbalanced (ratio: {ratio:.1f}:1)")
        print(f"   📉 Undersampling majority class to {max_ratio:.0f}:1 ratio...")
        
        if benign_count > malicious_count:
            # Undersample benign
            target_benign = int(malicious_count * max_ratio)
            benign_df = df[df['malware_label'] == 0].sample(n=target_benign, random_state=Config.RANDOM_STATE)
            malicious_df = df[df['malware_label'] == 1]
        else:
            # Undersample malicious
            target_malicious = int(benign_count * max_ratio)
            malicious_df = df[df['malware_label'] == 1].sample(n=target_malicious, random_state=Config.RANDOM_STATE)
            benign_df = df[df['malware_label'] == 0]
        
        df = pd.concat([benign_df, malicious_df]).sample(frac=1, random_state=Config.RANDOM_STATE).reset_index(drop=True)
        
        new_benign = (df['malware_label'] == 0).sum()
        new_malicious = (df['malware_label'] == 1).sum()
        print(f"   ✅ Balanced to {new_benign:,} benign, {new_malicious:,} malicious")
    
    return df

# ===========================================================================
# TRAINING CLASS
# ===========================================================================

class UniversalRansomwareTrainer:
    """Universal trainer that works with any dataset format"""
    
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_columns = Config.FEATURE_COLUMNS
        self.model_version = Config.MODEL_VERSION
        self.training_metrics = {}
        
    def load_and_prepare_data(self, csv_path: str) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Load and automatically prepare any dataset format"""
        print(f"\n{'='*70}")
        print(f"📂 LOADING DATASET")
        print(f"{'='*70}")
        print(f"📁 File: {csv_path}")
        
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"❌ Dataset not found: {csv_path}")
        
        # Load dataset
        df = pd.read_csv(csv_path)
        original_size = len(df)
        print(f"✅ Loaded {len(df):,} samples with {len(df.columns)} columns")
        
        # Step 1: Detect and standardize labels
        print(f"\n{'='*70}")
        print(f"🏷️  LABEL PROCESSING")
        print(f"{'='*70}")
        label_col = detect_label_column(df)
        df = standardize_labels(df, label_col)
        
        # Step 2: Map feature columns
        print(f"\n{'='*70}")
        print(f"🔧 FEATURE MAPPING")
        print(f"{'='*70}")
        df = map_feature_columns(df)
        
        # Step 3: Fill missing features
        df = fill_missing_features(df)
        
        # Step 4: Handle missing values and infinities
        print(f"\n{'='*70}")
        print(f"🧹 DATA CLEANING")
        print(f"{'='*70}")
        df = handle_infinite_and_nan(df)
        
        # Step 5: Remove duplicates
        df = remove_duplicates(df)
        
        # Step 6: Balance if needed
        df = balance_dataset(df, max_ratio=10.0)
        
        # Select final columns
        X = df[self.feature_columns]
        y = df['malware_label']
        
        print(f"\n{'='*70}")
        print(f"✅ DATA PREPARATION COMPLETE")
        print(f"{'='*70}")
        print(f"Final dataset: {len(df):,} samples ({original_size - len(df):,} removed)")
        print(f"Features: {len(self.feature_columns)}")
        print(f"Class distribution: {(y==0).sum():,} benign / {(y==1).sum():,} malicious")
        
        return X, y
    
    def train(self, X: pd.DataFrame, y: pd.Series) -> Dict:
        """Train the LightGBM model"""
        print(f"\n{'='*70}")
        print(f"🤖 MODEL TRAINING")
        print(f"{'='*70}")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=Config.TEST_SIZE, random_state=Config.RANDOM_STATE, stratify=y
        )
        
        print(f"Training set: {len(X_train):,} samples")
        print(f"Test set: {len(X_test):,} samples")
        
        # Scale features
        print(f"\n📊 Scaling features...")
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train LightGBM
        print(f"\n🚀 Training LightGBM model...")
        self.model = lgb.LGBMClassifier(**Config.LGBM_PARAMS)
        
        self.model.fit(
            X_train_scaled, y_train,
            eval_set=[(X_test_scaled, y_test)],
            eval_metric='logloss'
        )
        
        # Predictions
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)[:, 1]
        
        # Calculate metrics
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, zero_division=0),
            'recall': recall_score(y_test, y_pred, zero_division=0),
            'f1_score': f1_score(y_test, y_pred, zero_division=0),
            'roc_auc': roc_auc_score(y_test, y_pred_proba),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'samples_train': len(X_train),
            'samples_test': len(X_test)
        }
        
        self.training_metrics = metrics
        
        # Display results
        print(f"\n{'='*70}")
        print(f"📊 TRAINING RESULTS")
        print(f"{'='*70}")
        print(f"Accuracy:  {metrics['accuracy']*100:.2f}%")
        print(f"Precision: {metrics['precision']*100:.2f}%")
        print(f"Recall:    {metrics['recall']*100:.2f}%")
        print(f"F1 Score:  {metrics['f1_score']*100:.2f}%")
        print(f"ROC AUC:   {metrics['roc_auc']:.4f}")
        
        print(f"\n📈 Confusion Matrix:")
        cm = metrics['confusion_matrix']
        print(f"                Predicted")
        print(f"              Benign  Malicious")
        print(f"Actual Benign    {cm[0][0]:5d}   {cm[0][1]:5d}")
        print(f"     Malicious   {cm[1][0]:5d}   {cm[1][1]:5d}")
        
        # Feature importance
        print(f"\n🔝 Top 10 Important Features:")
        importances = self.model.feature_importances_
        feature_importance = sorted(zip(self.feature_columns, importances), key=lambda x: x[1], reverse=True)
        for i, (feature, importance) in enumerate(feature_importance[:10], 1):
            print(f"   {i:2d}. {feature:30s}: {importance:8.1f}")
        
        return metrics
    
    def save_model(self):
        """Save trained model and scaler"""
        print(f"\n{'='*70}")
        print(f"💾 SAVING MODEL")
        print(f"{'='*70}")
        
        model_path = Config.MODEL_DIR / f"lightgbm_model_v{self.model_version}.pkl"
        scaler_path = Config.MODEL_DIR / f"lightgbm_scaler_v{self.model_version}.pkl"
        metrics_path = Config.LOGS_DIR / f"training_metrics_v{self.model_version}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Save model and scaler
        joblib.dump(self.model, model_path)
        joblib.dump(self.scaler, scaler_path)
        
        # Save metrics
        with open(metrics_path, 'w') as f:
            json.dump(self.training_metrics, f, indent=2)
        
        print(f"✅ Model saved: {model_path}")
        print(f"✅ Scaler saved: {scaler_path}")
        print(f"✅ Metrics saved: {metrics_path}")
        
        return model_path, scaler_path

# ===========================================================================
# MAIN EXECUTION
# ===========================================================================

def main():
    print(f"\n{'='*70}")
    print(f"🤖 UNIVERSAL LIGHTGBM RANSOMWARE DETECTION TRAINER v2.0")
    print(f"{'='*70}")
    print(f"Handles ANY dataset format automatically!")
    print(f"{'='*70}\n")
    
    # Setup
    setup_directories()
    
    # Find dataset
    if len(sys.argv) > 1:
        dataset_path = Path(sys.argv[1])
    else:
        dataset_path = find_latest_dataset()
    
    if dataset_path is None or not dataset_path.exists():
        print(f"❌ No dataset found!")
        print(f"Usage: python train_model.py [path/to/ransomware_dataset.csv]")
        print(f"Or place dataset in: {Config.DATASET_DIR}")
        sys.exit(1)
    
    print(f"📁 Using dataset: {dataset_path.name}\n")
    
    # Train
    trainer = UniversalRansomwareTrainer()
    X, y = trainer.load_and_prepare_data(str(dataset_path))
    metrics = trainer.train(X, y)
    model_path, scaler_path = trainer.save_model()
    
    # Final summary
    print(f"\n{'='*70}")
    print(f"🎉 TRAINING COMPLETE!")
    print(f"{'='*70}")
    print(f"Model ready for deployment: {model_path.name}")
    print(f"Test accuracy: {metrics['accuracy']*100:.2f}%")
    print(f"F1 Score: {metrics['f1_score']*100:.2f}%")
    print(f"\n🚀 Next steps:")
    print(f"   1. Test: python run.py")
    print(f"   2. Simulate: python ransomware_test.py")
    print(f"{'='*70}\n")

if __name__ == "__main__":
    main()
