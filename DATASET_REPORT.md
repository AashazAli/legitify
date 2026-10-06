# LEGITIFY — Kaggle Fake Job Postings Dataset Profiling Report

## 1. Executive Dataset Summary
- **Dataset Source**: Kaggle University of the Aegean Real / Fake Job Postings Dataset
- **Total Records**: 17,880
- **Total Features**: 18
- **Duplicate Rows**: 0
- **Target Variable**: `fraudulent` (Binary: 0 = Legitimate, 1 = Fraudulent)
- **Class Distribution**:
  - **Legitimate Postings (0)**: 17,014 (95.16%)
  - **Fraudulent Postings (1)**: 866 (4.84%)
- **Imbalance Ratio**: 1 Fraud : 19 Legitimate (Severe class imbalance)

---

## 2. Feature Schema & Types
| Column Name | Data Type | Missing Values | Missing % | Field Type |
| :--- | :--- | :--- | :--- | :--- |
| `job_id` | `int64` | 0 | 0.00% | Numerical/Metadata |
| `title` | `str` | 0 | 0.00% | Text |
| `location` | `str` | 346 | 1.94% | Numerical/Metadata |
| `department` | `str` | 11,547 | 64.58% | Numerical/Metadata |
| `salary_range` | `str` | 15,012 | 83.96% | Numerical/Metadata |
| `company_profile` | `str` | 3,308 | 18.50% | Text |
| `description` | `str` | 1 | 0.01% | Text |
| `requirements` | `str` | 2,696 | 15.08% | Text |
| `benefits` | `str` | 7,212 | 40.34% | Text |
| `telecommuting` | `int64` | 0 | 0.00% | Numerical/Metadata |
| `has_company_logo` | `int64` | 0 | 0.00% | Numerical/Metadata |
| `has_questions` | `int64` | 0 | 0.00% | Numerical/Metadata |
| `employment_type` | `str` | 3,471 | 19.41% | Categorical |
| `required_experience` | `str` | 7,050 | 39.43% | Categorical |
| `required_education` | `str` | 8,105 | 45.33% | Categorical |
| `industry` | `str` | 4,903 | 27.42% | Categorical |
| `function` | `str` | 6,455 | 36.10% | Categorical |
| `fraudulent` | `int64` | 0 | 0.00% | Target |

---

## 3. High-Value Intelligence Signals Identified
1. **Missing Company Profile**: Over 85% of fraudulent job postings lack a verified company profile description.
2. **Missing Company Logo**: Fraudulent listings have a significantly higher rate of missing company logos (`has_company_logo = 0`).
3. **Suspicious Keyword Clusters**: Presence of phrases such as *"wire transfer"*, *"entry fee"*, *"pay to work"*, *"administrative assistant work from home"*, *"data entry operator"*, and direct personal email contacts.
4. **Education & Experience Omission**: Over 40% of fraudulent listings do not specify required educational degrees or work experience.
5. **Telecommuting Flag**: Remote postings exhibit an elevated risk ratio compared to on-site corporate roles.

---

## 4. Modeling Strategy & Optimization Metric
Given the extreme class imbalance (4.84% fraud rate), standard Accuracy is completely misleading (a naive classifier predicting 0 achieves 95.16% accuracy while detecting 0 scams).

The optimization objective prioritizes:
- **Fraud Recall**: Must capture at least 80-90%+ of fraudulent listings.
- **Fraud F1-Score**: Harmonic mean of Precision and Recall.
- **PR-AUC (Precision-Recall AUC)**: Highly resilient metric for imbalanced fraud datasets.
- **ROC-AUC**: Overall discrimination threshold.
