// ==============================================================================
// SUPABASE SERVER ADMIN CLIENT (Strictly Server-Side)
// ==============================================================================
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

dotenv.config();
dotenv.config({ path: '.env.local' });

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL ||
  process.env.SUPABASE_URL ||
  'https://nsvcphlhezykbbducxip.supabase.co';

const DEFAULT_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5zdmNwaGxoZXp5a2JiZHVjeGlwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODMwMjA3NTEsImV4cCI6MjA5ODU5Njc1MX0.dA4aw75RM0-KNjxJfpp4-9mJX7ZpDjODqbSIhYaWzzs';

const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY ||
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
  process.env.VITE_SUPABASE_ANON_KEY ||
  DEFAULT_ANON_KEY;

export const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey, {
  auth: {
    autoRefreshToken: false,
    persistSession: false,
  },
});
