import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
import time, os

# 1. Load data
DATA_PATH = 'ml/data/synthetic_flows.csv'
df = pd.read_csv(DATA_PATH)

FEATURES = ['protocol', 'src_port', 'dst_port', 'pkt_count',
            'byte_count', 'duration_ms', 'avg_ipt_ms']
X = df[FEATURES]
y = df['label']

le = LabelEncoder()
y_enc = le.fit_transform(y)

X_train, X_test, y_train, y_test = train_test_split(
    X, y_enc, test_size=0.2, random_state=42, stratify=y_enc)

# 2. Define models
models = {
    'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
    'Decision Tree': DecisionTreeClassifier(max_depth=10, random_state=42),
    'k-NN (k=5)':    Pipeline([
                        ('scaler', StandardScaler()),
                        ('knn', KNeighborsClassifier(n_neighbors=5))
                     ]),
}

results = {}
os.makedirs('ml/results', exist_ok=True)

# 3. Train and evaluate
for name, model in models.items():
    t0 = time.time()
    model.fit(X_train, y_train)
    train_time = time.time() - t0

    t0 = time.time()
    y_pred = model.predict(X_test)
    infer_time = (time.time() - t0) / len(X_test) * 1000

    cv_scores = cross_val_score(model, X_train, y_train, cv=5)

    results[name] = {
        'y_pred': y_pred,
        'cv_mean': cv_scores.mean(),
        'cv_std': cv_scores.std(),
        'train_time_s': train_time,
        'infer_ms_per_flow': infer_time,
    }
    print(f"\n{'='*50}")
    print(f"Model: {name}")
    print(f"  CV Accuracy:  {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
    print(f"  Train time:   {train_time:.3f}s")
    print(f"  Infer time:   {infer_time:.4f} ms/flow")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

# 4. Confusion matrices
fig, axes = plt.subplots(1, len(models), figsize=(16, 4))
for ax, (name, res) in zip(axes, results.items()):
    cm = confusion_matrix(y_test, res['y_pred'])
    ConfusionMatrixDisplay(cm, display_labels=le.classes_).plot(ax=ax, colorbar=False)
    ax.set_title(name)
plt.tight_layout()
plt.savefig('ml/results/confusion_matrices.png', dpi=150)
print("\nSaved: ml/results/confusion_matrices.png")

# 5. Feature importance
rf = models['Random Forest']
importances = pd.Series(rf.feature_importances_, index=FEATURES).sort_values(ascending=True)
fig, ax = plt.subplots(figsize=(7, 4))
importances.plot.barh(ax=ax, color='steelblue')
ax.set_title('Feature Importances (Random Forest)')
ax.set_xlabel('Importance Score')
plt.tight_layout()
plt.savefig('ml/results/feature_importance.png', dpi=150)
print("Saved: ml/results/feature_importance.png")

# 6. Accuracy vs Overhead
names   = list(results.keys())
acc     = [results[n]['cv_mean'] for n in names]
latency = [results[n]['infer_ms_per_flow'] for n in names]

fig, ax = plt.subplots(figsize=(6, 4))
ax.scatter(latency, acc, s=100, zorder=5)
for i, n in enumerate(names):
    ax.annotate(n, (latency[i], acc[i]), textcoords='offset points', xytext=(8, 0))
ax.set_xlabel('Inference Latency (ms/flow)')
ax.set_ylabel('Cross-Val Accuracy')
ax.set_title('Accuracy vs. Overhead Tradeoff')
ax.set_ylim(0.5, 1.05)
plt.tight_layout()
plt.savefig('ml/results/accuracy_vs_overhead.png', dpi=150)
print("Saved: ml/results/accuracy_vs_overhead.png")
