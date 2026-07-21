import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# ============================================================
# File Paths
# ============================================================

DATASET_PATH = r"D:\PhishingDetecterAI\dataset\phishing.csv"

MODEL_PATH = r"D:\PhishingDetecterAI\models\phishing_model.pkl"

FEATURE_PATH = r"D:\PhishingDetecterAI\models\feature_names.pkl"

# ============================================================
# Load Dataset
# ============================================================

df = pd.read_csv(DATASET_PATH)

print("✅ Dataset Loaded Successfully")
print(df.head())

# Remove extra spaces in column names
df.columns = df.columns.str.strip()

# ============================================================
# Features & Target
# ============================================================

X = df.drop(columns=["index", "Result"])
y = df["Result"]

print("\n========== DATASET ==========")
print(f"Samples  : {len(df)}")
print(f"Features : {X.shape[1]}")

# ============================================================
# Train Test Split
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print(f"\nTraining Samples : {len(X_train)}")
print(f"Testing Samples  : {len(X_test)}")

# ============================================================
# Train Random Forest
# ============================================================

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

print("\n✅ Model Training Completed")

# ============================================================
# Prediction
# ============================================================

predictions = model.predict(X_test)

# ============================================================
# Evaluation
# ============================================================

print("\n========== MODEL PERFORMANCE ==========\n")

print(f"Accuracy  : {accuracy_score(y_test, predictions):.4f}")
print(f"Precision : {precision_score(y_test, predictions, pos_label=1):.4f}")
print(f"Recall    : {recall_score(y_test, predictions, pos_label=1):.4f}")
print(f"F1 Score  : {f1_score(y_test, predictions, pos_label=1):.4f}")

print("\nConfusion Matrix")
print(confusion_matrix(y_test, predictions))

print("\nClassification Report")
print(classification_report(y_test, predictions))

# ============================================================
# Feature Importance
# ============================================================

importance = pd.DataFrame({
    "Feature": X.columns,
    "Importance": model.feature_importances_
}).sort_values(by="Importance", ascending=False)

print("\n========== TOP 10 IMPORTANT FEATURES ==========\n")
print(importance.head(10))

# ============================================================
# Save Model
# ============================================================

# ============================================================
# Save Model
# ============================================================

MODEL_PATH = r"D:\PhishingDetecterAI\models\phishing_model.pkl"
FEATURE_PATH = r"D:\PhishingDetecterAI\models\feature_names.pkl"

joblib.dump(model, MODEL_PATH)
joblib.dump(list(X.columns), FEATURE_PATH)

print("\n✅ Model Saved Successfully")
print("Model Location :", MODEL_PATH)

print("\n✅ Feature Names Saved Successfully")
print("Feature Location :", FEATURE_PATH)
# ============================================================
# Save Feature Order
# ============================================================

joblib.dump(list(X.columns), FEATURE_PATH)

print("\n✅ Feature Names Saved Successfully")
print(FEATURE_PATH)

print("\n🎉 Training Completed Successfully!")