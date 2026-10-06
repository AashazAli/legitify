// ==============================================================================
// LEGITIFY DEMO SEED SCRIPT (Explicitly Marked [DEMO DATA])
// ==============================================================================
import dotenv from 'dotenv';
import { supabaseAdmin } from '../lib/supabase/server';

dotenv.config();
dotenv.config({ path: '.env.local' });

async function seedDemoData() {
  console.log("🌱 [LEGITIFY] Seeding synthetic demo records into Supabase...");

  const demoThreats = [
    {
      indicator_type: "DOMAIN",
      indicator_value: "amazon-internship-selection.top",
      normalized_value: "amazon-internship-selection.top",
      threat_type: "Brand Lookalike Phishing",
      severity: "CRITICAL",
      source: "Legitify Threat Watch [DEMO DATA]",
      description: "Spoofs Amazon recruitment portal to solicit ₹3,500 laptop verification fee [DEMO DATA].",
      is_demo: true,
    },
    {
      indicator_type: "EMAIL",
      indicator_value: "tcs.hiring.onboarding@gmail.com",
      normalized_value: "tcs.hiring.onboarding@gmail.com",
      threat_type: "Impersonation / Free Webmail",
      severity: "HIGH",
      source: "Community Threat Submission [DEMO DATA]",
      description: "Uses Gmail handle claiming to be Tata Consultancy Services campus recruiter [DEMO DATA].",
      is_demo: true,
    },
    {
      indicator_type: "KEYWORD",
      indicator_value: "security deposit refundable training fee",
      normalized_value: "security deposit refundable training fee",
      threat_type: "Upfront Fee Scam Heuristic",
      severity: "CRITICAL",
      source: "Heuristic Defense Matrix [DEMO DATA]",
      description: "Matches clause requesting refundable cash deposit before internship commencement [DEMO DATA].",
      is_demo: true,
    },
    {
      indicator_type: "UPI",
      indicator_value: "techcareers.hr@okhdfcbank",
      normalized_value: "techcareers.hr@okhdfcbank",
      threat_type: "Direct UPI Cash Demand",
      severity: "CRITICAL",
      source: "UPI Payment Guard [DEMO DATA]",
      description: "Direct UPI address provided in fake offer letter for document processing charge [DEMO DATA].",
      is_demo: true,
    }
  ];

  try {
    for (const threat of demoThreats) {
      await supabaseAdmin
        .from('threat_indicators')
        .upsert(threat, { onConflict: 'normalized_value' });
    }
    console.log("✅ [LEGITIFY] Successfully seeded 4 synthetic threat indicators [DEMO DATA].");
  } catch (err: any) {
    console.error("❌ [LEGITIFY] Seed error:", err?.message || err);
  }
}

seedDemoData();
