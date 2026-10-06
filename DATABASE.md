# LEGITIFY Database Architecture & Schema Documentation

The LEGITIFY platform uses **Supabase PostgreSQL** with strict **Row Level Security (RLS)**.

---

## Tables Overview

| Table Name | Description | RLS Policy |
| :--- | :--- | :--- |
| `profiles` | User profiles synced with `auth.users` | Owner read & update |
| `scans` | Primary scan records with trust scores, risk levels, and status | Owner read, write, update, delete |
| `scan_inputs` | Private user submissions (files, hashes, extracted text) | Owner only (Private) |
| `companies` | Directory of verified & normalized companies | Authenticated users (Public read) |
| `company_aliases` | Known trading names & brand aliases | Authenticated users (Public read) |
| `company_intelligence` | Shared sanitized corporate evidence cache | Authenticated users (Public read) |
| `domains` | Domain age, registrar, TLS/SSL status, threat reputation | Authenticated users (Public read) |
| `recruiters` | Recruiter email alignment & reputation | Authenticated users (Public read) |
| `evidence` | Granular factual findings and community signals per scan | Scan owner only |
| `reports` | Full 22-section structured report JSON and public share tokens | Owner read/write OR public token |
| `threat_indicators` | Known scam indicators, lookalikes, and upfront fee patterns | Authenticated users (Public read) |
| `audit_logs` | Immutable audit trail with IP hashing | Owner read/insert only |
| `feedback` | User accuracy feedback | Owner read/insert only |

---

## Key Security Guidelines
1. **Private User Files**: All rows in `scan_inputs` and objects in `storage.objects` are isolated strictly to `auth.uid() = user_id`.
2. **Sanitized Public Intelligence**: Derived corporate facts stored in `companies` and `company_intelligence` must never contain candidate names, personal notes, or private offer letters.
3. **Public Share Links**: Cryptographically random 32-character hex tokens (`share_token`) are required to read shared reports anonymously.
