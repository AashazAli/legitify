# LEGITIFY — Step-by-Step Beginner Setup Guide

This guide is designed for developers setting up LEGITIFY from scratch.

---

## Step 1: Install Node.js
Ensure you have **Node.js (v18+)** installed. Check via:
```bash
node --version
npm --version
```

---

## Step 2: Open Project & Install Dependencies
Navigate into the project root directory and run:
```bash
npm install
```

---

## Step 3: Set Up Supabase Database & Migrations
1. Go to [https://supabase.com](https://supabase.com) and create a free project.
2. In your Supabase Dashboard, click **SQL Editor** on the left menu.
3. Click **New Query**, copy the entire contents of `supabase/migrations/20260817000001_initial_schema.sql`, and paste it into the editor.
4. Click **Run** to create all 13 tables, indexes, and Row Level Security (RLS) policies.
5. In **Project Settings → API**, copy your:
   - **Project URL**
   - **Anon / Public Key**
   - **Service Role Key (Secret)**

---

## Step 4: Configure Google OAuth in Supabase (Optional for Google Login)
1. Go to the [Google Cloud Console](https://console.cloud.google.com/apis/credentials).
2. Create an **OAuth 2.0 Client ID** (Web Application).
3. In **Authorized redirect URIs**, enter:
   - Local: `http://localhost:3000/auth/callback`
   - Supabase Auth: `https://<YOUR_SUPABASE_PROJECT_REF>.supabase.co/auth/v1/callback`
4. In your Supabase Dashboard, go to **Authentication → Providers → Google**, enable it, and paste your Google Client ID and Google Client Secret.

---

## Step 5: Configure `.env.local`
Create a `.env.local` file in the root folder with:
```env
NEXT_PUBLIC_SUPABASE_URL=https://<your-project>.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=<your-anon-key>
SUPABASE_SERVICE_ROLE_KEY=<your-service-role-key>

GEMINI_API_KEY=<your-gemini-api-key>

VIRUSTOTAL_API_KEY=<your-virustotal-key>
ABUSEIPDB_API_KEY=<your-abuseipdb-key>
GOOGLE_SAFE_BROWSING_API_KEY=<your-safe-browsing-key>

PORT=3001
VITE_API_URL=http://localhost:3001
```

---

## Step 6: Run Locally
Start the application:
```bash
npm run dev
```
Open **http://localhost:3000** in your browser.

---

## Step 7: Deploy to Vercel
1. Push your project to GitHub.
2. Sign in to [Vercel](https://vercel.com) and click **Add New → Project**.
3. Select your repository.
4. Add your environment variables in the Vercel deployment settings.
5. Click **Deploy**.
