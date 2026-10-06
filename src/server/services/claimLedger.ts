// ==============================================================================
// LEGITIFY CLAIM LEDGER SERVICE
// Extracts, normalizes, and manages claims from document chunks
// DETERMINISTIC: same chunks produce same claims and IDs
// ==============================================================================

import { DocumentChunk, ForensicClaim, ClaimType } from '../../types/forensicTypes';
import { analyzeChunk } from './chunkingService';
import { normalizeCompanyName, normalizeDomain } from '../utils/normalizer';

export interface ClaimLedgerResult {
  claims: ForensicClaim[];
  normalizedEntities: {
    organizations: string[];
    emails: string[];
    domains: string[];
    phones: string[];
    cins: string[];
    upiIds: string[];
    paymentRequests: { amount: string; method: string; chunkId: string }[];
    jobRoles: string[];
    stipends: Array<{ amount?: number; currency: string; period: string; plausibility: string; raw: string }>;
    joiningDates: Array<{ date?: string; isUrgent: boolean; raw: string }>;
    signatories: Array<{ name?: string; title?: string; raw: string }>;
    selectionStatements: string[];
    logoReferences: string[];
  };
}

/**
 * Builds the claim ledger from extracted document chunks.
 * Every claim traces back to a specific chunk (and page).
 */
export function buildClaimLedger(chunks: DocumentChunk[]): ClaimLedgerResult {
  const claims: ForensicClaim[] = [];
  let claimCounter = 0;

  const organizations = new Set<string>();
  const emails = new Set<string>();
  const domains = new Set<string>();
  const phones = new Set<string>();
  const cins = new Set<string>();
  const upiIds = new Set<string>();
  const paymentRequests: { amount: string; method: string; chunkId: string }[] = [];
  const jobRoles = new Set<string>();
  const stipendsList: ClaimLedgerResult['normalizedEntities']['stipends'] = [];
  const joiningDatesList: ClaimLedgerResult['normalizedEntities']['joiningDates'] = [];
  const signatoriesList: ClaimLedgerResult['normalizedEntities']['signatories'] = [];
  const selectionStatements = new Set<string>();
  const logoReferences = new Set<string>();

  for (const chunk of chunks) {
    const findings = analyzeChunk(chunk);

    // 1. Organization claims (if section is LETTERHEAD or ORGANIZATION_DETAILS)
    if (chunk.section === 'LETTERHEAD' || chunk.section === 'ORGANIZATION_DETAILS') {
      const orgMatch = chunk.text.match(/(?:at|for|with|from)\s+([A-Z][A-Za-z0-9&., ]+(?:Limited|Ltd|Pvt|Private|Inc|Corporation|LLC|LLP))/);
      if (orgMatch) {
        const rawOrg = orgMatch[1].trim();
        const normOrg = normalizeCompanyName(rawOrg);
        organizations.add(normOrg);
        claimCounter++;
        claims.push({
          claimId: `CLM-${String(claimCounter).padStart(3, '0')}`,
          chunkId: chunk.chunkId,
          page: chunk.pageStart,
          type: 'ORGANIZATION',
          rawText: rawOrg,
          normalizedValue: normOrg,
          extractionConfidence: 0.90,
          verification: {
            status: 'UNVERIFIED',
            checks: [],
            evidenceIds: [],
          },
        });
      }
    }

    // 2. Email claims
    for (const email of findings.entities.emails) {
      emails.add(email.toLowerCase());
      claimCounter++;
      claims.push({
        claimId: `CLM-${String(claimCounter).padStart(3, '0')}`,
        chunkId: chunk.chunkId,
        page: chunk.pageStart,
        type: 'RECRUITER_EMAIL',
        rawText: email,
        normalizedValue: email.toLowerCase(),
        extractionConfidence: 0.98,
        verification: {
          status: 'UNVERIFIED',
          checks: [],
          evidenceIds: [],
        },
      });
    }

    // 3. Domain claims
    for (const domain of findings.entities.domains) {
      const normDom = normalizeDomain(domain);
      domains.add(normDom);
      claimCounter++;
      claims.push({
        claimId: `CLM-${String(claimCounter).padStart(3, '0')}`,
        chunkId: chunk.chunkId,
        page: chunk.pageStart,
        type: 'COMPANY_DOMAIN',
        rawText: domain,
        normalizedValue: normDom,
        extractionConfidence: 0.95,
        verification: {
          status: 'UNVERIFIED',
          checks: [],
          evidenceIds: [],
        },
      });
    }

    // 4. CIN claims
    for (const cin of findings.entities.cinNumbers) {
      cins.add(cin.toUpperCase());
      claimCounter++;
      claims.push({
        claimId: `CLM-${String(claimCounter).padStart(3, '0')}`,
        chunkId: chunk.chunkId,
        page: chunk.pageStart,
        type: 'CIN_NUMBER',
        rawText: cin,
        normalizedValue: cin.toUpperCase(),
        extractionConfidence: 0.99,
        verification: {
          status: 'UNVERIFIED',
          checks: [],
          evidenceIds: [],
        },
      });
    }

    // 5. Phone claims
    for (const phone of findings.entities.phones) {
      const cleanPhone = phone.replace(/[^0-9+]/g, '');
      phones.add(cleanPhone);
      claimCounter++;
      claims.push({
        claimId: `CLM-${String(claimCounter).padStart(3, '0')}`,
        chunkId: chunk.chunkId,
        page: chunk.pageStart,
        type: 'PHONE_NUMBER',
        rawText: phone,
        normalizedValue: cleanPhone,
        extractionConfidence: 0.92,
        verification: {
          status: 'UNVERIFIED',
          checks: [],
          evidenceIds: [],
        },
      });
    }

    // 6. Payment requests
    if (findings.paymentSignals.hasPaymentRequest && !findings.paymentSignals.hasPaymentNegation) {
      for (const amt of findings.paymentSignals.amounts) {
        paymentRequests.push({
          amount: amt.value,
          method: findings.paymentSignals.methods.join(', ') || 'UNSPECIFIED',
          chunkId: chunk.chunkId,
        });

        claimCounter++;
        claims.push({
          claimId: `CLM-${String(claimCounter).padStart(3, '0')}`,
          chunkId: chunk.chunkId,
          page: chunk.pageStart,
          type: 'PAYMENT_REQUEST',
          rawText: amt.context || amt.value,
          normalizedValue: amt.value,
          extractionConfidence: findings.paymentSignals.confidence,
          verification: {
            status: 'CONTRADICTED', // Payment requests contradict legitimate employment standards
            checks: [
              {
                name: 'Zero-Fee Recruitment Standard',
                status: 'FAIL',
                finding: `Monetary demand of ${amt.value} contradicts ILO and national fair recruitment standards`,
              }
            ],
            evidenceIds: [],
          },
        });
      }
    }

    // 7. UPI IDs
    for (const upi of findings.entities.upiIds) {
      upiIds.add(upi.toLowerCase());
      claimCounter++;
      claims.push({
        claimId: `CLM-${String(claimCounter).padStart(3, '0')}`,
        chunkId: chunk.chunkId,
        page: chunk.pageStart,
        type: 'UPI_ID',
        rawText: upi,
        normalizedValue: upi.toLowerCase(),
        extractionConfidence: 0.98,
        verification: {
          status: 'CONTRADICTED',
          checks: [
            {
              name: 'Corporate Payment Channel',
              status: 'FAIL',
              finding: 'Personal/direct UPI ID in employment document is an anomalous payment channel',
            }
          ],
          evidenceIds: [],
        },
      });
    }

    // 8. Job Roles / Titles
    if (findings.offerParts?.roles) {
      for (const role of findings.offerParts.roles) {
        jobRoles.add(role);
        claimCounter++;
        claims.push({
          claimId: `CLM-${String(claimCounter).padStart(3, '0')}`,
          chunkId: chunk.chunkId,
          page: chunk.pageStart,
          type: 'ROLE_TITLE',
          rawText: role,
          normalizedValue: role,
          extractionConfidence: 0.88,
          verification: {
            status: 'OBSERVED',
            checks: [
              {
                name: 'Offer Role Designation',
                status: 'PASS',
                finding: `Position title stated as '${role}'`,
              }
            ],
            evidenceIds: [],
          },
        });
      }
    }

    // 9. Compensation / Stipend Claims
    if (findings.offerParts?.stipends) {
      for (const st of findings.offerParts.stipends) {
        stipendsList.push(st);
        claimCounter++;
        const stStatus = st.plausibility === 'CONTRADICTORY' ? 'CONTRADICTED'
          : st.plausibility === 'UNUSUAL' ? 'SUSPICIOUS'
          : st.plausibility === 'PLAUSIBLE' ? 'OBSERVED'
          : 'UNVERIFIED';

        claims.push({
          claimId: `CLM-${String(claimCounter).padStart(3, '0')}`,
          chunkId: chunk.chunkId,
          page: chunk.pageStart,
          type: 'STIPEND',
          rawText: st.raw,
          normalizedValue: st.amount ? `${st.currency} ${st.amount} (${st.period})` : st.raw,
          extractionConfidence: 0.85,
          verification: {
            status: stStatus,
            checks: [
              {
                name: 'Economic Plausibility Analysis',
                status: st.plausibility === 'PLAUSIBLE' ? 'PASS' : st.plausibility === 'UNUSUAL' ? 'PARTIAL' : 'FAIL',
                finding: st.reason,
              }
            ],
            evidenceIds: [],
          },
        });
      }
    }

    // 10. Joining Dates & Urgency Signals
    if (findings.offerParts?.joiningDates) {
      for (const jd of findings.offerParts.joiningDates) {
        joiningDatesList.push(jd);
        claimCounter++;
        claims.push({
          claimId: `CLM-${String(claimCounter).padStart(3, '0')}`,
          chunkId: chunk.chunkId,
          page: chunk.pageStart,
          type: 'JOINING_DATE',
          rawText: jd.raw,
          normalizedValue: jd.raw,
          extractionConfidence: 0.85,
          verification: {
            status: jd.isUrgent ? 'SUSPICIOUS' : 'OBSERVED',
            checks: [
              {
                name: 'Timeline Consistency Check',
                status: jd.isUrgent ? 'PARTIAL' : 'PASS',
                finding: jd.isUrgent ? 'Compressed reporting timeline detected (urgency indicator)' : 'Standard onboarding date specified',
              }
            ],
            evidenceIds: [],
          },
        });
      }
    }

    // 11. Signatory Claims (Absence of public record = UNVERIFIED, NEVER FAKE)
    if (findings.offerParts?.signatories) {
      for (const sig of findings.offerParts.signatories) {
        signatoriesList.push(sig);
        
        // Signatory Name claim (if parsed)
        if (sig.name) {
          claimCounter++;
          claims.push({
            claimId: `CLM-${String(claimCounter).padStart(3, '0')}`,
            chunkId: chunk.chunkId,
            page: chunk.pageStart,
            type: 'SIGNATORY_NAME',
            rawText: sig.raw,
            normalizedValue: sig.name,
            extractionConfidence: 0.85,
            verification: {
              status: 'OBSERVED',
              checks: [
                {
                  name: 'Signatory Name Extraction',
                  status: 'PASS',
                  finding: `Signatory name observed in document: ${sig.name}`,
                },
                {
                  name: 'Corporate Signatory Verification',
                  status: 'UNAVAILABLE',
                  finding: 'Signatory identity documented in offer; unverified against internal corporate signatory roll (Absence is not proof of fraud).',
                }
              ],
              evidenceIds: [],
            },
          });
        }

        // Signatory Title / Position claim
        if (sig.title) {
          claimCounter++;
          claims.push({
            claimId: `CLM-${String(claimCounter).padStart(3, '0')}`,
            chunkId: chunk.chunkId,
            page: chunk.pageStart,
            type: 'SIGNATORY_TITLE' as any,
            rawText: sig.raw,
            normalizedValue: sig.title,
            extractionConfidence: 0.85,
            verification: {
              status: 'OBSERVED',
              checks: [
                {
                  name: 'Signatory Title Extraction',
                  status: 'PASS',
                  finding: `Signatory title/position documented: ${sig.title}`,
                }
              ],
              evidenceIds: [],
            },
          });
        }

        // Signature Presence observation
        claimCounter++;
        claims.push({
          claimId: `CLM-${String(claimCounter).padStart(3, '0')}`,
          chunkId: chunk.chunkId,
          page: chunk.pageStart,
          type: 'SIGNATURE_PRESENT' as any,
          rawText: sig.raw,
          normalizedValue: sig.name || sig.title || 'Signature Block Present',
          extractionConfidence: 0.80,
          verification: {
            status: 'OBSERVED',
            checks: [
              {
                name: 'Signature Block Observed',
                status: 'PASS',
                finding: 'Signature block observed in document (Visual observation only — does not imply authorization or cryptographic validity).',
              }
            ],
            evidenceIds: [],
          },
        });
      }
    }

    // 12. Offer & Selection Statements
    if (findings.offerParts?.selectionStatements) {
      for (const sel of findings.offerParts.selectionStatements) {
        selectionStatements.add(sel);
        claimCounter++;
        claims.push({
          claimId: `CLM-${String(claimCounter).padStart(3, '0')}`,
          chunkId: chunk.chunkId,
          page: chunk.pageStart,
          type: 'OFFER_SELECTION_CLAIM',
          rawText: sel,
          normalizedValue: sel,
          extractionConfidence: 0.90,
          verification: {
            status: 'OBSERVED',
            checks: [
              {
                name: 'Offer Language Pattern',
                status: 'PASS',
                finding: 'Formal selection language identified in offer text.',
              }
            ],
            evidenceIds: [],
          },
        });
      }
    }

    // 13. Letterhead & Logo References
    if (findings.offerParts?.logoReferences) {
      for (const logo of findings.offerParts.logoReferences) {
        logoReferences.add(logo);
        claimCounter++;
        claims.push({
          claimId: `CLM-${String(claimCounter).padStart(3, '0')}`,
          chunkId: chunk.chunkId,
          page: chunk.pageStart,
          type: 'LOGO_IDENTITY_CLAIM',
          rawText: logo,
          normalizedValue: logo,
          extractionConfidence: 0.80,
          verification: {
            status: 'OBSERVED',
            checks: [
              {
                name: 'Visual Brand Presence',
                status: 'PASS',
                finding: logo,
              }
            ],
            evidenceIds: [],
          },
        });
      }
    }
  }

  return {
    claims,
    normalizedEntities: {
      organizations: Array.from(organizations),
      emails: Array.from(emails),
      domains: Array.from(domains),
      phones: Array.from(phones),
      cins: Array.from(cins),
      upiIds: Array.from(upiIds),
      paymentRequests,
      jobRoles: Array.from(jobRoles),
      stipends: stipendsList,
      joiningDates: joiningDatesList,
      signatories: signatoriesList,
      selectionStatements: Array.from(selectionStatements),
      logoReferences: Array.from(logoReferences),
    },
  };
}
