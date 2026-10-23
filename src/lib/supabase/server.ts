// ==============================================================================
// SUPABASE SERVER ADMIN CLIENT (Strictly Server-Side)
// ==============================================================================
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

dotenv.config();
dotenv.config({ path: '.env.local' });

const rawUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL;
const isPlaceholderUrl = !rawUrl || rawUrl.includes('your-project-ref') || rawUrl.includes('your-project') || rawUrl.includes('placeholder');
const supabaseUrl = isPlaceholderUrl
  ? 'https://nsvcphlhezykbbducxip.supabase.co'
  : rawUrl;

const DEFAULT_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5zdmNwaGxoZXp5a2JiZHVjeGlwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODMwMjA3NTEsImV4cCI6MjA5ODU5Njc1MX0.dA4aw75RM0-KNjxJfpp4-9mJX7ZpDjODqbSIhYaWzzs';

const rawKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_ANON_KEY;
const isPlaceholderKey = !rawKey || rawKey.includes('your_supabase') || rawKey.includes('placeholder') || rawKey.length < 20;
const supabaseServiceKey = isPlaceholderKey ? DEFAULT_ANON_KEY : rawKey;

export const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey, {
  auth: {
    autoRefreshToken: false,
    persistSession: false,
  },
});
