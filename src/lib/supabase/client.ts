// ==============================================================================
// SUPABASE BROWSER CLIENT
// ==============================================================================
import { createClient } from '@supabase/supabase-js';

const metaEnv = (import.meta as any).env || {};
const supabaseUrl = metaEnv.VITE_SUPABASE_URL ||
  metaEnv.NEXT_PUBLIC_SUPABASE_URL ||
  'https://nsvcphlhezykbbducxip.supabase.co';

const supabaseAnonKey = metaEnv.VITE_SUPABASE_ANON_KEY ||
  metaEnv.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5zdmNwaGxoZXp5a2JiZHVjeGlwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODMwMjA3NTEsImV4cCI6MjA5ODU5Njc1MX0.dA4aw75RM0-KNjxJfpp4-9mJX7ZpDjODqbSIhYaWzzs';

export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,
  },
});
