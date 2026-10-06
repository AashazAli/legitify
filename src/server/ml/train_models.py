import os
import sys
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix
)
import xgboost as xgb
from scipy.sparse import hstack

def main():
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATASET_PATH = r"C:\Users\Priya\Downloads\legitify\kaggle data set\fake_job_postings.csv"
    DATASET_REPORT_PATH = os.path.join(BASE_DIR, "..", "..", "..", "DATASET_REPORT.md")
    MODEL_ARTIFACT_PATH = os.path.join(BASE_DIR, "modelArtifact.json")

    print("=" * 70, flush=True)
    print("LEGITIFY SUPERVISED ML FRAUD TRAINING & EVALUATION PIPELINE", flush=True)
    print("=" * 70, flush=True)
    print(f"Loading dataset from: {DATASET_PATH}", flush=True)

    df = pd.read_csv(DATASET_PATH)

    total_rows, total_cols = df.shape
    missing_counts = df.isnull().sum().to_dict()
    dtypes = {col: str(dtype) for col, dtype in df.dtypes.items()}
    duplicate_rows = int(df.duplicated().sum())
    class_counts = df['fraudulent'].value_counts().to_dict()
    fraud_ratio = float(class_counts.get(1, 0) / total_rows)

    categorical_cols = ['employment_type', 'required_experience', 'required_education', 'industry', 'function']
    numerical_cols = ['telecommuting', 'has_company_logo', 'has_questions']
    text_cols = ['title', 'company_profile', 'description', 'requirements', 'benefits']

    print(f"Total Rows: {total_rows} | Total Columns: {total_cols}", flush=True)
    print(f"Legitimate (0): {class_counts.get(0, 0)} | Fraudulent (1): {class_counts.get(1, 0)} ({fraud_ratio:.2%})", flush=True)

    # Preprocessing
    df['telecommuting'] = df['telecommuting'].fillna(0).astype(int)
    df['has_company_logo'] = df['has_company_logo'].fillna(0).astype(int)
    df['has_questions'] = df['has_questions'].fillna(0).astype(int)
    df['has_company_profile'] = df['company_profile'].notnull().astype(int)
    df['has_salary_range'] = df['salary_range'].notnull().astype(int)

    df['full_text'] = (
        df['title'].fillna('') + ' ' +
        df['company_profile'].fillna('') + ' ' +
        df['description'].fillna('') + ' ' +
        df['requirements'].fillna('') + ' ' +
        df['benefits'].fillna('')
    ).str.lower().str.replace(r'[^a-z0-9\s]', ' ', regex=True)

    y = df['fraudulent'].values

    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        df, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"Train samples: {len(X_train_raw)} | Test samples: {len(X_test_raw)}", flush=True)

    vectorizer = TfidfVectorizer(
        max_features=2000,
        ngram_range=(1, 2),
        min_df=3,
        max_df=0.85,
        sublinear_tf=True
    )

    X_train_tfidf = vectorizer.fit_transform(X_train_raw['full_text'])
    X_test_tfidf = vectorizer.transform(X_test_raw['full_text'])

    aux_features = ['telecommuting', 'has_company_logo', 'has_questions', 'has_company_profile', 'has_salary_range']
    X_train_aux = X_train_raw[aux_features].values
    X_test_aux = X_test_raw[aux_features].values

    X_train = hstack([X_train_tfidf, X_train_aux]).tocsr()
    X_test = hstack([X_test_tfidf, X_test_aux]).tocsr()

    feature_names = list(vectorizer.get_feature_names_out()) + aux_features

    models = {
        "Logistic Regression (Balanced)": LogisticRegression(
            C=1.5, class_weight='balanced', max_iter=500, random_state=42
        ),
        "Linear SVM (Calibrated)": CalibratedClassifierCV(
            estimator=LinearSVC(C=1.0, class_weight='balanced', random_state=42, max_iter=1000),
            cv=2
        ),
        "Random Forest (Balanced)": RandomForestClassifier(
            n_estimators=30, max_depth=12, class_weight='balanced', random_state=42, n_jobs=1
        ),
        "Gradient Boosting": GradientBoostingClassifier(
            n_estimators=30, learning_rate=0.1, max_depth=4, random_state=42
        ),
        "XGBoost (Scale Pos Weight)": xgb.XGBClassifier(
            n_estimators=30,
            max_depth=4,
            learning_rate=0.1,
            scale_pos_weight=15,
            random_state=42,
            eval_metric='logloss',
            n_jobs=1
        )
    }

    results = {}
    best_model_name = None
    best_f1 = -1

    print("\n" + "=" * 70, flush=True)
    print("EVALUATING SUPERVISED ALGORITHMS ON TEST SET", flush=True)
    print("=" * 70, flush=True)

    for name, clf in models.items():
        print(f"Training {name}...", flush=True)
        clf.fit(X_train, y_train)
        
        y_pred = clf.predict(X_test)
        if hasattr(clf, "predict_proba"):
            y_prob = clf.predict_proba(X_test)[:, 1]
        else:
            y_prob = clf.decision_function(X_test)
        
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        roc_auc = roc_auc_score(y_test, y_prob)
        pr_auc = average_precision_score(y_test, y_prob)
        cm = confusion_matrix(y_test, y_pred).tolist()
        
        results[name] = {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1": round(float(f1), 4),
            "roc_auc": round(float(roc_auc), 4),
            "pr_auc": round(float(pr_auc), 4),
            "confusion_matrix": cm
        }
        
        print(f"  [{name}] Accuracy: {acc:.4f} | Precision: {prec:.4f} | Recall: {rec:.4f} | F1: {f1:.4f} | ROC-AUC: {roc_auc:.4f} | PR-AUC: {pr_auc:.4f}", flush=True)
        print(f"  Confusion Matrix: {cm}", flush=True)
        
        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name

    print(f"\n>>> Best Performing Production Model: {best_model_name} (Fraud F1: {best_f1:.4f})", flush=True)

    log_reg = models["Logistic Regression (Balanced)"]
    coefficients = log_reg.coef_[0]

    top_fraud_indices = np.argsort(coefficients)[-30:][::-1]
    top_legit_indices = np.argsort(coefficients)[:30]

    top_fraud_features = [{"feature": feature_names[i], "weight": round(float(coefficients[i]), 4)} for i in top_fraud_indices]
    top_legit_features = [{"feature": feature_names[i], "weight": round(float(coefficients[i]), 4)} for i in top_legit_indices]

    weights_dict = {}
    for i, name in enumerate(feature_names):
        weights_dict[name] = float(coefficients[i])

    intercept = float(log_reg.intercept_[0])

    vocab = vectorizer.vocabulary_
    vocab_formatted = {k: int(v) for k, v in vocab.items()}
    idf_formatted = [float(v) for v in vectorizer.idf_]

    artifact = {
        "modelVersion": "1.2.0-kaggle-supervised",
        "algorithm": best_model_name,
        "dataset": "Kaggle Real / Fake Job Postings Dataset",
        "trainedAt": "2026-08-18",
        "totalTrainingRows": total_rows,
        "bestModel": best_model_name,
        "intercept": intercept,
        "auxiliaryFeatures": aux_features,
        "evaluationMetrics": results,
        "topFraudFeatures": top_fraud_features,
        "topLegitFeatures": top_legit_features,
        "vocabularySize": len(vocab_formatted),
        "featureWeights": weights_dict,
        "idf": idf_formatted,
        "vocabulary": vocab_formatted,
    }

    with open(MODEL_ARTIFACT_PATH, "w", encoding="utf-8") as f:
        json.dump(artifact, f)

    print(f"\nExported production model artifact to: {MODEL_ARTIFACT_PATH}", flush=True)
    print("=" * 70, flush=True)
    print("TRAINING & ARTIFACT EXPORT COMPLETE", flush=True)
    print("=" * 70, flush=True)

if __name__ == '__main__':
    main()
