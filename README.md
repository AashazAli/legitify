# LEGITIFY

> **Evidence-Based Recruitment & Internship Forensic Trust Intelligence Platform**

[![Vercel Deployment](https://img.shields.io/badge/Vercel-Deployed-000000?style=for-the-badge&logo=vercel&logoColor=white)](https://legitify-two.vercel.app)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue?style=for-the-badge&logo=typescript)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-18.3-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-6.3-646CFF?style=for-the-badge&logo=vite&logoColor=white)](https://vitejs.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-3.4-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![Supabase](https://img.shields.io/badge/Supabase-PostgreSQL-3ECF8E?style=for-the-badge&logo=supabase&logoColor=white)](https://supabase.com/)
[![Hugging Face](https://img.shields.io/badge/Hugging_Face-docTR_%26_ColPali-FFD21E?style=for-the-badge&logo=huggingface&logoColor=black)](https://huggingface.co/)
[![Google Gemini](https://img.shields.io/badge/Google_Gemini-2.0_%26_1.5-4285F4?style=for-the-badge&logo=google&logoColor=white)](https://ai.google.dev/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

---

## 🌐 Live Deployments
* **Production App**: [https://legitify-two.vercel.app](https://legitify-two.vercel.app)
* **Alternative Mirror**: [https://legitify.vercel.app](https://legitify.vercel.app)
* **Custom Domain Mapping**: Production DNS routing compatible with `legitify.org` / `legitify.dev` via Vercel Edge.

---

## 📖 Overview

**LEGITIFY** is an advanced, evidence-grounded cybersecurity and forensic investigation engine built to protect students, job seekers, and university placement cells from fraudulent internships, employment scams, impersonation schemes, and predatory fee demands.

Unlike conventional heuristic scanners or generic LLM chatbots that hallucinate opinions, LEGITIFY implements a **multi-layered, evidence-first forensic framework**. It decomposes uploaded documents into verifiable claims, runs independent deep learning models, interrogates authoritative registries, validates domain infrastructure, and executes deterministic scoring before AI synthesizes the final report.

### Key Threats Defended Against
1. **The Entity Confusion Trap**: Fraudsters use legitimate corporate names (e.g. IndiGo, TCS, Infosys) but communicate via public webmail (`@gmail.com`) or lookalike domains (`goindigohr.in`).
2. **The Credential Illusion**: Fraudsters attach authentic third-party completion certificates or unverified registration seals to lend credibility to fake offers.
3. **Predatory Fee Demands**: Fake recruiters solicit candidate registration charges, training fees, or equipment caution deposits prior to onboarding.
4. **Forged Document Signatures**: Fabricated appointment letters with pasted digital signature stamps and forged HR authority blocks.

---

## 🔬 Core Forensic Architecture

```
                    UPLOADED OFFER DOCUMENT (PDF / Image / Text)
                                        │
                                        ▼
    ┌───────────────────────────────────────────────────────────────────────┐
    │                     DOCUMENT DECOMPOSITION PIPELINE                   │
    ├───────────────────────────────────┼───────────────────────────────────┤
    │  Hugging Face pszemraj/pdf-ocr    │  Hugging Face baidu/Unlimited-OCR │
    │  (Mindee docTR Deep Learning OCR) │  (End-to-End Image Document OCR)  │
    ├───────────────────────────────────┴───────────────────────────────────┤
    │  Visual Forensics & Layout Engine (Signature & Stamp Verification)    │
    └───────────────────────────────────┬───────────────────────────────────┘
                                        │
                                        ▼
    ┌───────────────────────────────────────────────────────────────────────┐
    │                      STRUCTURED CLAIM EXTRACTION                      │
    │  (Roles, Stipend, Joining Date, Signatory, Selection Statement, Logo) │
    └───────────────────────────────────┬───────────────────────────────────┘
                                        │
                                        ▼
    ┌───────────────────────────────────────────────────────────────────────┐
    │             Hugging Face davanstrien/ColPali-Query-Generator          │
    │        (Qwen2.5-VL-7B Multimodal Document Retrieval Queries)          │
    └───────────────────────────────────┬───────────────────────────────────┘
                                        │
                                        ▼
    ┌───────────────────────────────────┴───────────────────────────────────┐
    │                  CONCURRENT MULTI-SOURCE INVESTIGATION                │
    ├───────────────────────────────────┬───────────────────────────────────┤
    │ 🏛️ MCA21 Corporate Registry       │ 🌐 ICANN RDAP & DNS MX Records    │
    │ 👤 Recruiter SPF / DMARC Routing  │ ⚡ Cybersecurity Threat Feeds     │
    │ 🌎 Community Forums & Reviews     │ 🤖 Supervised ML Classifier       │
    └───────────────────────────────────┴───────────────────────────────────┘
                                        │
                                        ▼
    ┌───────────────────────────────────────────────────────────────────────┐
    │                        DUAL-RAG RETRIEVAL LAYER                       │
    │   Document RAG (SHA-256 Chunks) + External Evidence RAG (Live Data)   │
    └───────────────────────────────────┬───────────────────────────────────┘
                                        │
                                        ▼
    ┌───────────────────────────────────────────────────────────────────────┐
    │            10-DIMENSION DETERMINISTIC SCORING (100% EXPLAINABLE)      │
    │                     LEGITIFY-SCORE-v2.0 (Weights = 1.0)               │
    └───────────────────────────────────┬───────────────────────────────────┘
                                        │
                                        ▼
    ┌───────────────────────────────────────────────────────────────────────┐
    │             REPORT ASSERTION GUARD & CONTRADICTION ENGINE             │
    │       (Semantic Consistency Verification & Zero False-Positive Guard) │
    └───────────────────────────────────┬───────────────────────────────────┘
                                        │
                                        ▼
    ┌───────────────────────────────────────────────────────────────────────┐
    │               GEMINI DEEP WEB CROSS-EXAMINATION & SYNTHESIS           │
    │    (Evidence Interrogation, Multi-Signal Reasoning, Action Guidance)  │
    └───────────────────────────────────┬───────────────────────────────────┘
                                        │
                                        ▼
                          AUDIT-GRADE FORENSIC REPORT
```

---

## 📐 10-Dimension Forensic Integrity Grid (LEGITIFY-SCORE-v2.0)

LEGITIFY calculates trust deterministically using strict mathematical weights that sum to 1.0:

| Dimension | Weight | Forensic Analysis Objectives | Authoritative Data Sources |
|---|---|---|---|
| **1. Document Authenticity** | **10%** | Structural format, header emblems, tamper-evidence, layout anomalies | Deep Learning OCR, Visual Forensics |
| **2. Company Legal & Registry** | **15%** | Corporate Identity Number (CIN), active legal standing, RoC jurisdiction | Ministry of Corporate Affairs (MCA21) |
| **3. Domain & Infrastructure** | **12%** | Domain age, RDAP/WHOIS registry, lookalike typosquatting distance | ICANN RDAP, Authoritative DNS |
| **4. Recruiter Authority** | **12%** | Corporate domain alignment, public webmail detection, SPF/MX routing | Mail Routing Records, SMTP MX |
| **5. Financial Integrity** | **15%** | Upfront registration charges, caution deposits, training fees, UPI IDs | Document Semantic Miner, Cyberthreat Feeds |
| **6. Role & Compensation** | **10%** | Plausibility of stipend, remote terms, standard compensation curves | Claim Ledger, Market Baseline Indices |
| **7. Selection & Urgency** | **8%** | Immediate joining pressure (<24h), no-interview selection statements | NLP Urgency Pattern Matcher |
| **8. Cybersecurity & Threats** | **8%** | Phishing indicators, malware hashes, suspicious URL redirect chains | Global Threat Feeds, Google Safe Browsing |
| **9. Community Experience** | **5%** | Corroborating public complaint clusters, employee reviews, discussion threads | Reddit, LinkedIn, Consumer Complaints |
| **10. Machine Learning** | **5%** | Supervised statistical fraud risk score (trained on Kaggle scam corpus) | Linear SVM & Feature Extraction Pipeline |

---

## 🤖 Hugging Face Deep Learning Integration

LEGITIFY deeply integrates cutting-edge open models hosted on Hugging Face Spaces:

### 1. `pszemraj/pdf-ocr` (Mindee docTR Optical Character Recognition)
* **Space Endpoint**: `https://pszemraj-pdf-ocr.hf.space`
* **Role**: Primary Tier-1 OCR engine for all uploaded PDF offer letters.
* **Capability**: Performs end-to-end deep learning page text extraction, retaining paragraph boundaries, tabular columns, and verbatim typography.
* **Resilience**: Features automatic multi-tier fallback to Gemini Vision and localized native PDF parsers under network constraints.

### 2. `davanstrien/ColPali-Query-Generator` (Qwen2.5-VL-7B Multimodal Queries)
* **Space Endpoint**: `https://davanstrien-colpali-query-generator.hf.space`
* **Role**: Generates dynamic document retrieval queries across three distinct axes:
  * **Broad Topical Queries**: Evaluates company domain and overall offer context.
  * **Specific Detail Queries**: Targets exact compensation amounts, stipend currency, and joining clauses.
  * **Visual Element Queries**: Focuses on corporate letterheads, official seals, and signature blocks.
* **Zero Hardcoding**: Dynamically populates the `ClaimInvestigationQueue` for real-time web intelligence and RAG grounding.

---

## 🖋️ Visual Forensics & Signatory Differentiation

A critical breakthrough in LEGITIFY is the strict separation between visual signature marks and cryptographic digital signatures:

* **Visual Signature Detected**: The system recognizes signature marks, stamps, and handwritten initials in the document via visual coordinate bounding.
* **Evidentiary Rule**:
  > *Presence of a visual signature is an observed document attribute, NOT an automatic trust boost. Absence of a signature is an informational advisory, NEVER proof of fraud.*
* **Zero False Red Flags**: Legitimate corporate signatories (e.g., HR Director `E. Sai Reddy`) are recognized in document decomposition, preventing false-positive fraud escalations.

---

## 📋 Scan-Scoped Auditable Evidence Locker

Every scan produces tamper-evident evidence items bound to the specific investigation:

```
[Scan ID]-DOC-P1-OFFER_PART-28a9c3   [AUTHORITATIVE]  Document Decomposition
MCA-INTERGLOBE-CIN-ACTIVE            [AUTHORITATIVE]  MCA21 Master Registry
DNS-GOINDIGO.IN-MX-VERIFIED          [STRONG]         ICANN RDAP / Authoritative DNS
EXT-WEB-INTEL-RECRUITER-VERIFIED     [STRONG]         Live Web Intelligence
```

* **Authoritative Tier**: Government registers (MCA21), ICANN RDAP, Verbatim Document Forensics.
* **Strong Tier**: Corporate mail exchangers, Supervised ML Classifier.
* **Medium & Community Tier**: Public discussion forums, consumer complaint patterns.

---

## 🛡️ Report Assertion Guard

LEGITIFY includes an automated semantic assertion guard ([`reportAssertionGuard.ts`](src/server/services/reportAssertionGuard.ts)) executed before final report compilation:
* Prevents declaring a company "unregistered" if an active RoC/MCA21 record exists.
* Prevents declaring "no HR contact person" if a visual signatory block was detected.
* Reconciles external community reports with corporate verification status.

---

## 👥 Role-Based Portals & Navigation

### 🎓 Candidate / Student Portal
* **Document Scanner**: Drag & drop PDF or high-resolution images.
* **Comprehensive Report View**: Uncollapsed, sequential presentation of:
  * Executive Verdict & Trust Index (0–100)
  * Why This Assessment? (Transparent human-readable score explanation)
  * Signatory & Visual Forensics Card
  * Claim-by-Claim Verification Ledger (RAG ground truth)
  * 10-Dimension Forensic Integrity Grid
  * Auditable Evidence Locker with source links
  * Multi-Signal Reasoning & Gemini Deep Cross-Examination
  * Actionable Candidate Safety Guidance & Helplines (1930 Cybercrime)
* **Trust AI Copilot**: Dynamic conversational assistant grounded in the active scan's evidence.

### 🛡️ Security Operations Center (Admin Portal)
* **Live Pipeline Telemetry**: Real-time event streams and system execution traces.
* **Threat Intelligence IOCs**: Malicious UPI handles, lookalike domains, phishing URLs.
* **Global Case Registry**: Auditing, risk score adjustments, and forensic notes persisted to Supabase.
* **Top Navigation Switcher**: Direct, one-click toggle between Candidate View and Admin Operations.

---

## 💻 Tech Stack

* **Frontend**: React 18, TypeScript, Vite, Tailwind CSS, Lucide Icons, Canvas Confetti
* **Backend**: Node.js, Express, TypeScript, Multer, Tsx
* **Deep Learning & OCR**: `pszemraj/pdf-ocr` (docTR), `baidu/Unlimited-OCR`, `davanstrien/ColPali-Query-Generator` (Hugging Face Spaces via Python `gradio_client` bridge)
* **AI Reasoning**: Google Gemini 2.0 Flash / 1.5 Flash (`@google/genai`)
* **Database & Auth**: Supabase (PostgreSQL), Google OAuth 2.0
* **Machine Learning**: Supervised Linear SVM trained on Kaggle Job Scam Dataset
* **Deployment**: Vercel Serverless Functions (`api/index.ts` + `vercel.json`)

---

## 🚀 Getting Started

### Prerequisites
* **Node.js**: v18.0.0 or higher
* **npm**: v9.0.0 or higher
* **Git**

### 1. Clone the Repository
```bash
git clone https://github.com/Shri-Sanjaykumar/legitify1.git
cd legitify1
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Configure Environment Variables
Create a `.env` or `.env.local` file:
```env
PORT=3001
VITE_API_URL=http://localhost:3001

# Google Gemini API
GEMINI_API_KEY=your_gemini_api_key_here
VITE_GEMINI_API_KEY=your_gemini_api_key_here

# Hugging Face Spaces
HF_TOKEN=your_huggingface_token_here

# Supabase Database & Auth
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your_supabase_anon_key
SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key
```

### 4. Run Development Server
```bash
npm run dev
```
* **Frontend**: [http://localhost:3000](http://localhost:3000)
* **Backend API**: [http://localhost:3001](http://localhost:3001)

### 5. Run Automated Test Suite
```bash
npm test
```
Executes all **62 tests across 19 suites** covering deterministic scoring, visual forensics, assertion guard, Hugging Face models, and end-to-end scan pipeline.

### 6. Build for Production
```bash
npm run build
```

---

## 🧪 Test Coverage (62 Tests / 19 Suites)

* `TEST 1`: Verified company + Corporate domain + Valid certificate + No fee $\rightarrow$ **LOW RISK**
* `TEST 2`: Registered company + Fake recruiter Gmail + Upfront fee + Lookalike domain $\rightarrow$ **HIGH RISK**
* `TEST 3`: Authentic certificate + Suspicious opportunity $\rightarrow$ **Certificate: AUTHENTIC, Opportunity: HIGH RISK**
* `TEST 4`: Unknown certificate with unlisted registry $\rightarrow$ **UNVERIFIED (Not classified as fake)**
* `TEST 5`: Nonexistent company + Lookalike domain + Urgent UPI payment $\rightarrow$ **LIKELY SCAM**
* `TEST 6`: Single isolated public review $\rightarrow$ **Preserved as weak signal (No false escalation)**
* `TEST 7`: Multiple independent complaints detailing identical payment pattern $\rightarrow$ **STRONG COMMUNITY SIGNAL**
* `TEST 8`: Registered company + Impersonated domain $\rightarrow$ **Company: REGISTERED, Domain: SUSPICIOUS**
* `VISUAL FORENSICS`: Signature detection without false red flags; signatory state mapping.
* `ASSERTION GUARD`: Semantic check prevents contradictory claims in output reports.
* `HUGGING FACE`: Pipeline routing to `pszemraj/pdf-ocr` and `davanstrien/ColPali-Query-Generator`.

---

## ⚖️ Statutory Notice & Responsible Disclosure

* **Risk Advisory Purpose**: LEGITIFY provides automated digital risk assessments. It serves as an investigative assistant and does not replace official law enforcement or legal counsel.
* **Zero Upfront Fees Standard**: Under the International Labour Organization (ILO) Fair Recruitment Initiative, legitimate employers never charge candidate fees or training deposits.
* **Statutory Reporting**: Report recruitment cybercrime in India to the **National Cybercrime Helpline (1930)** or via **[cybercrime.gov.in](https://cybercrime.gov.in)**.

---

## 📄 License
This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
