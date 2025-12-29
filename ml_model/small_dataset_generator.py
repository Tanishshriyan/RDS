import pandas as pd
import numpy as np
import os
import argparse
import random

FEATURE_COLUMNS = [
    "cpu_percent",
    "memory_percent",
    "threads",
    "uptime",
    "cpu_spike_count",
    "file_writes",
    "file_reads",
    "file_deletes",
    "file_renames",
    "file_modifications",
    "extension_changes",
    "entropy_mean",
    "entropy_variance",
    "entropy_max",
    "high_entropy_file_ratio",
    "rapid_file_ops_count",
    "mass_file_change_events",
    "suspicious_extensions_count",
    "network_connections",
    "outbound_data_kb",
    "read_write_delete_pattern",
    "process_injection_attempts",
    "malware_label",
]

def generate_advanced_dataset(n_samples: int, output_path: str):
    print(f"🔧 Generating {n_samples:,} samples with 22 features...")
    
    rows = []
    
    # 60% benign, 40% ransomware
    n_benign = int(n_samples * 0.6)
    n_mal = n_samples - n_benign
    
    # Benign samples
    for _ in range(n_benign):
        rows.append({
            # Process
            "cpu_percent": np.random.normal(20, 10),
            "memory_percent": np.random.normal(30, 10),
            "threads": np.random.randint(10, 80),
            "uptime": np.random.exponential(3600),
            "cpu_spike_count": np.random.poisson(1),  # rare spikes
            
            # File ops
            "file_writes": np.random.poisson(5),
            "file_reads": np.random.poisson(10),
            "file_deletes": np.random.poisson(0.5),
            "file_renames": np.random.poisson(1),
            "file_modifications": np.random.poisson(4),
            "extension_changes": 0,
            
            # Entropy
            "entropy_mean": np.random.normal(4.5, 1.0),
            "entropy_variance": np.random.exponential(0.5),
            "entropy_max": np.random.normal(5.5, 0.8),
            "high_entropy_file_ratio": np.random.beta(2, 10),
            
            # Patterns
            "rapid_file_ops_count": np.random.poisson(3),
            "mass_file_change_events": 0,
            "suspicious_extensions_count": 0,
            
            # Network
            "network_connections": np.random.poisson(3),
            "outbound_data_kb": np.random.exponential(20),
            
            # Ransomware signatures absent
            "read_write_delete_pattern": 0,
            "process_injection_attempts": 0,
            
            "malware_label": 0,
        })
    
    # Ransomware samples
    for _ in range(n_mal):
        rows.append({
            # Process
            "cpu_percent": np.random.normal(85, 8),
            "memory_percent": np.random.normal(75, 10),
            "threads": np.random.randint(80, 220),
            "uptime": np.random.exponential(600),
            "cpu_spike_count": np.random.randint(20, 80),  # many spikes
            
            # File ops – aggressive
            "file_writes": np.random.randint(300, 900),
            "file_reads": np.random.randint(400, 1000),
            "file_deletes": np.random.randint(80, 300),
            "file_renames": np.random.randint(250, 700),
            "file_modifications": np.random.randint(400, 1200),
            "extension_changes": np.random.randint(200, 600),
            
            # Entropy – encrypted
            "entropy_mean": np.random.uniform(7.9, 7.999),
            "entropy_variance": np.random.uniform(0.001, 0.05),
            "entropy_max": np.random.uniform(7.99, 8.0),
            "high_entropy_file_ratio": np.random.uniform(0.9, 1.0),
            
            # Patterns – ransomware
            "rapid_file_ops_count": np.random.randint(800, 3000),
            "mass_file_change_events": np.random.randint(20, 80),
            "suspicious_extensions_count": np.random.randint(40, 180),
            
            # Network – exfil
            "network_connections": np.random.randint(10, 40),
            "outbound_data_kb": np.random.exponential(1500),
            
            # Ransomware signatures
            "read_write_delete_pattern": random.choice([2, 3, 4]),
            "process_injection_attempts": np.random.randint(2, 10),
            
            "malware_label": 1,
        })
    
    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    
    size_mb = os.path.getsize(output_path) / 1e6
    print(f"✅ Saved to: {output_path}")
    print(f"💾 Size: {size_mb:.1f} MB")
    print(f"📊 Shape: {df.shape}")
    print(df.head())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=400_000,
                        help="Number of samples (400k ≈ ~50MB)")
    parser.add_argument("--output", default="data/training_data/ransomware_dataset_22.csv")
    args = parser.parse_args()
    
    generate_advanced_dataset(args.samples, args.output)

if __name__ == "__main__":
    main()
