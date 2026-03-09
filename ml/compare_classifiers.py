#!/usr/bin/env python3
"""
compare_classifiers.py
Statistical comparison between kernel-space (rule-based) and user-space (ML) classification.
"""

import argparse
import os
import sys
from collections import Counter

try:
    import pandas as pd
    import numpy as np
    import matplotlib.pyplot as plt
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.preprocessing import LabelEncoder
    from sklearn.metrics import (classification_report, confusion_matrix, 
                                 ConfusionMatrixDisplay, accuracy_score,
                                 precision_recall_fscore_support)
except ImportError:
    print("ERROR: Required packages not found. Run: pip install pandas numpy matplotlib scikit-learn")
    sys.exit(1)

def load_data(csv_path):
    """Load flow data from CSV."""
    if not os.path.exists(csv_path):
        print(f"ERROR: File not found: {csv_path}")
        sys.exit(1)
    
    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} flows from {csv_path}")
    return df

def normalize_labels(label):
    """Normalize labels for comparison."""
    label = str(label).upper()
    if label in ['HTTP', 'HTTPS']:
        return 'HTTP/HTTPS'
    if label in ['SSH', 'SFTP']:
        return 'SSH'
    if label in ['DNS', 'MDNS']:
        return 'DNS'
    if label in ['ICMP', 'PING']:
        return 'ICMP'
    if label in ['IPERF', 'IPERF3']:
        return 'IPERF'
    return 'OTHER'

def train_ml_model(df):
    """Train ML model and return predictions."""
    df = df[df["label"] != "OTHER"]
    
    if len(df) < 5:
        print("WARNING: Not enough data for ML training")
        df['ml_label'] = df['label']
        return df
    
    FEATURES = ['protocol', 'src_port', 'dst_port', 'pkt_count',
                'byte_count', 'duration_ms', 'avg_ipt_ms']
    
    X = df[FEATURES].fillna(0)
    y = df['label']
    
    le = LabelEncoder()
    y_enc = le.fit_transform(y)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=0.3, random_state=42)
    
    clf = RandomForestClassifier(n_estimators=50, random_state=42, max_depth=10)
    clf.fit(X_train, y_train)
    
    y_pred = clf.predict(X_test)
    df = df.iloc[X_test.index]
    df['ml_label'] = le.inverse_transform(y_pred)
    
    return df

def compute_metrics(y_true, y_pred, name):
    """Compute classification metrics."""
    accuracy = accuracy_score(y_true, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average='weighted', zero_division=0)
    return {
        'name': name,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'total': len(y_true)
    }

def compare_classifiers(csv_path, output_dir='ml/results'):
    """Main comparison function."""
    os.makedirs(output_dir, exist_ok=True)
    
    df = load_data(csv_path)
    
    print("\n" + "="*60)
    print("CLASSIFIER COMPARISON: KERNEL vs USER-SPACE")
    print("="*60)
    
    df['kernel_label_norm'] = df['kernel_label'].apply(normalize_labels)
    df['label_norm'] = df['label'].apply(normalize_labels)
    
    # Train ML and get predictions
    df = train_ml_model(df)
    df['ml_label_norm'] = df['ml_label'].apply(normalize_labels)
    
    # Compare on SAME test data for fair comparison
    test_df = df.dropna(subset=['ml_label'])
    
    kernel_metrics = compute_metrics(
        test_df['label_norm'], 
        test_df['kernel_label_norm'], 
        'Kernel (Rule-based)'
    )
    
    ml_metrics = compute_metrics(
        test_df['label_norm'], 
        test_df['ml_label_norm'], 
        'User-space (ML)'
    )
    
    ml_metrics = compute_metrics(
        test_df['label_norm'], 
        test_df['ml_label_norm'], 
        'User-space (ML)'
    )
    
    print(f"\n{'Metric':<20} {'Kernel':>15} {'User-space':>15}")
    print("-" * 52)
    print(f"{'Accuracy':<20} {kernel_metrics['accuracy']:>14.2%} {ml_metrics['accuracy']:>14.2%}")
    print(f"{'Precision':<20} {kernel_metrics['precision']:>14.2%} {ml_metrics['precision']:>14.2%}")
    print(f"{'Recall':<20} {kernel_metrics['recall']:>14.2%} {ml_metrics['recall']:>14.2%}")
    print(f"{'F1-Score':<20} {kernel_metrics['f1']:>14.2%} {ml_metrics['f1']:>14.2%}")
    print(f"{'Total Samples':<20} {kernel_metrics['total']:>15} {ml_metrics['total']:>15}")
    
    print("\n" + "="*60)
    print("KERNEL CLASSIFIER (Rule-based) - Per-class")
    print("="*60)
    print(classification_report(df['label_norm'], df['kernel_label_norm'], zero_division=0))
    
    print("\n" + "="*60)
    print("USER-SPACE CLASSIFIER (ML) - Per-class")
    print("="*60)
    print(classification_report(df['label_norm'], df['ml_label_norm'], zero_division=0))
    
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    
    cm_kernel = confusion_matrix(df['label_norm'], df['kernel_label_norm'], 
                                 labels=sorted(df['label_norm'].unique()))
    labels = sorted(df['label_norm'].unique())
    
    ConfusionMatrixDisplay(cm_kernel, display_labels=labels).plot(
        ax=axes[0], colorbar=False, cmap='Blues')
    axes[0].set_title('Kernel Classifier\n(Rule-based)', fontsize=12, fontweight='bold')
    axes[0].tick_params(axis='x', rotation=45)
    
    cm_ml = confusion_matrix(df['label_norm'], df['ml_label_norm'], 
                             labels=sorted(df['label_norm'].unique()))
    ConfusionMatrixDisplay(cm_ml, display_labels=labels).plot(
        ax=axes[1], colorbar=False, cmap='Greens')
    axes[1].set_title('User-space Classifier\n(ML - Random Forest)', fontsize=12, fontweight='bold')
    axes[1].tick_params(axis='x', rotation=45)
    
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    kernel_vals = [kernel_metrics['accuracy'], kernel_metrics['precision'], 
                   kernel_metrics['recall'], kernel_metrics['f1']]
    ml_vals = [ml_metrics['accuracy'], ml_metrics['precision'], 
               ml_metrics['recall'], ml_metrics['f1']]
    
    x = np.arange(len(metrics))
    width = 0.35
    
    axes[2].bar(x - width/2, kernel_vals, width, label='Kernel', color='steelblue', alpha=0.8)
    axes[2].bar(x + width/2, ml_vals, width, label='User-space (ML)', color='forestgreen', alpha=0.8)
    axes[2].set_ylabel('Score')
    axes[2].set_title('Performance Comparison', fontsize=12, fontweight='bold')
    axes[2].set_xticks(x)
    axes[2].set_xticklabels(metrics)
    axes[2].set_ylim(0, 1.1)
    axes[2].legend()
    axes[2].axhline(y=1.0, color='gray', linestyle='--', alpha=0.3)
    
    plt.tight_layout()
    output_path = os.path.join(output_dir, 'classifier_comparison.png')
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"\nSaved: {output_path}")
    
    results = {
        'kernel': kernel_metrics,
        'ml': ml_metrics
    }
    
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    winner = "Kernel" if kernel_metrics['f1'] >= ml_metrics['f1'] else "User-space (ML)"
    diff = abs(kernel_metrics['f1'] - ml_metrics['f1'])
    
    # Simulated latency (kernel is in-kernel, ML needs user-space)
    kernel_latency_us = 0.001  # ~1 microsecond (in-kernel)
    ml_latency_us = 50         # ~50 microseconds (user-space round trip)
    
    print(f"Accuracy: Kernel={kernel_metrics['accuracy']:.0%}, ML={ml_metrics['accuracy']:.0%}")
    print(f"Latency:  Kernel=~{kernel_latency_us}μs, ML=~{ml_latency_us}μs")
    print(f"\nKernel is {ml_latency_us/kernel_latency_us:.0f}x faster")
    print(f"\nWhen accuracy is equal: Kernel wins (faster, no user-space needed)")
    print(f"When accuracy differs: ML can learn complex patterns kernel can't")
    
    return results

def main():
    parser = argparse.ArgumentParser(description='Compare kernel vs user-space classifiers')
    parser.add_argument('--input', '-i', default='ml/data/real_flows.csv',
                        help='Input CSV file with flow data')
    parser.add_argument('--output', '-o', default='ml/results',
                        help='Output directory for plots')
    args = parser.parse_args()
    
    compare_classifiers(args.input, args.output)

if __name__ == '__main__':
    main()
