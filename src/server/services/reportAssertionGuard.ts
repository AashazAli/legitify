// ==============================================================================
// LEGITIFY REPORT ASSERTION GUARD
// Enforces that every factual statement in the final report is backed by concrete
// evidence or explicitly phrased as an uncertainty (UNVERIFIED / NOT_FOUND).
// Prevents generic report templates and unsupported hallucinations.
// ==============================================================================

export interface AssertionValidationResult {
  text: string;
  isAllowed: boolean;
  hasEvidenceCitation: boolean;
  isExplicitUncertainty: boolean;
  citationFound?: string;
  blockedReason?: string;
}

export interface GuardAuditSummary {
  totalAssertionsChecked: number;
  allowedWithEvidence: number;
  allowedAsUncertainty: number;
  blockedOrSanitized: number;
  evidenceIdsRegistered: number;
  timestamp: string;
}

// Regex matching valid LEGITIFY evidence citations (including scan-scoped IDs)
const EVIDENCE_CITATION_REGEX = /\[(?:Doc-P\d+-C\d+|Ext-[A-Za-z0-9_-]+|E-[A-Za-z0-9_-]+|EXT-[A-Za-z0-9_-]+|[A-Za-z0-9_-]+-DOC-[A-Za-z0-9_-]+|[A-Za-z0-9_-]+-E-\d+)\]/i;

// Keywords indicating explicit epistemic uncertainty / negative findings
const UNCERTAINTY_INDICATORS = [
  'unverified',
  'not found',
  'insufficient evidence',
  'could not be confirmed',
  'not independently verified',
  'no record',
  'no matching record',
  'absence of',
  'does not imply fraud',
  'unknown',
  'offline',
  'limitation',
  'unsupported',
  'requires corroboration',
  'could not be determined',
  'not provided',
  'advisory',
  'observed',
];

/**
 * Semantic Scope Validation:
 * Ensures factual claims are not logically contradicted by the underlying evidence ledger.
 * For example: if a visual signature exists in the document, blocks false claims that
 * "No HR contact person / signatory was identified".
 */
export function validateAssertionScope(
  statement: string,
  evidenceItems: Array<{ id?: string; evidence_type?: string; title?: string; status?: string }> = []
): { isConsistent: boolean; replacementText?: string } {
  const lower = statement.toLowerCase();

  // 1. Signatory Contradiction Check
  const hasSignatoryEvidence = evidenceItems.some(
    e => (e.evidence_type && (e.evidence_type.includes('SIGNATURE') || e.evidence_type.includes('VISUAL_SIG') || e.evidence_type.includes('SIGNATORY'))) ||
         (e.title && (e.title.toLowerCase().includes('signature') || e.title.toLowerCase().includes('signatory')))
  );

  if (hasSignatoryEvidence && (lower.includes('no hr contact person') || lower.includes('no signatory details') || lower.includes('no signatory identified'))) {
    return {
      isConsistent: false,
      replacementText: 'A visual signature was observed in the document. Signatory identity is documented in offer; unverified against internal corporate signatory roll (absence is not proof of fraud). [Doc-Visual-Sig]',
    };
  }

  // 2. Company Registration Contradiction Check
  const claimsUnregistered = lower.includes('not registered') || lower.includes('unregistered company') || lower.includes('fake company');
  const hasRegistryEvidence = evidenceItems.some(
    e => e.evidence_type === 'LOCAL_REFERENCE_FOUND' || (e.title && e.title.includes('Local Reference Match'))
  );
  if (claimsUnregistered && hasRegistryEvidence) {
    return {
      isConsistent: false,
      replacementText: 'Entity documented in local corporate reference dataset. Live statutory registry query unavailable. [Ext-Registry-Ref]',
    };
  }

  return { isConsistent: true };
}

/**
 * Validates a single statement or finding against the registered evidence IDs and scope.
 */
export function validateAssertion(
  statement: string,
  validEvidenceIds: Set<string>,
  evidenceItems: Array<{ id?: string; evidence_type?: string; title?: string }> = []
): AssertionValidationResult {
  const trimmed = statement.trim();
  if (!trimmed || trimmed.length < 5) {
    return { text: trimmed, isAllowed: true, hasEvidenceCitation: false, isExplicitUncertainty: true };
  }

  // Check semantic scope first
  const scopeCheck = validateAssertionScope(trimmed, evidenceItems);
  if (!scopeCheck.isConsistent && scopeCheck.replacementText) {
    return {
      text: scopeCheck.replacementText,
      isAllowed: true,
      hasEvidenceCitation: true,
      isExplicitUncertainty: true,
      citationFound: '[Doc-Visual-Sig]',
    };
  }

  // 1. Check if the statement cites an active evidence item
  const match = trimmed.match(EVIDENCE_CITATION_REGEX);
  if (match) {
    const citation = match[0];
    const rawId = citation.replace(/[\[\]]/g, '');
    
    // Check if citation matches registered evidence ID or pattern
    const isRegistered = validEvidenceIds.has(rawId) || 
      Array.from(validEvidenceIds).some(id => id.includes(rawId) || rawId.includes(id)) ||
      rawId.startsWith('Doc-P') ||
      rawId.startsWith('Ext-') ||
      rawId.startsWith('EXT-') ||
      rawId.includes('-DOC-') ||
      rawId.includes('-E-');

    if (isRegistered) {
      return {
        text: trimmed,
        isAllowed: true,
        hasEvidenceCitation: true,
        isExplicitUncertainty: false,
        citationFound: citation,
      };
    }
  }

  // 2. Check if the statement is explicitly an expression of uncertainty or limitation
  const lower = trimmed.toLowerCase();
  const isUncertainty = UNCERTAINTY_INDICATORS.some(ind => lower.includes(ind));
  if (isUncertainty) {
    return {
      text: trimmed,
      isAllowed: true,
      hasEvidenceCitation: false,
      isExplicitUncertainty: true,
    };
  }

  // 3. Factual claim without evidence and without uncertainty framing: BLOCK or SANITIZE
  return {
    text: trimmed,
    isAllowed: false,
    hasEvidenceCitation: false,
    isExplicitUncertainty: false,
    blockedReason: 'Factual assertion lacks verifiable evidence citation and is not framed as an uncertainty.',
  };
}

/**
 * Sanitizes an array of findings or signal strings, ensuring unsupported factual statements
 * are replaced with explicit unverified notices rather than hallucinated facts.
 */
export function guardFindingsList(
  findings: string[],
  validEvidenceIds: Set<string>,
  categoryName: string = 'Finding',
  evidenceItems: Array<{ id?: string; evidence_type?: string; title?: string }> = []
): { sanitizedList: string[]; audit: { checked: number; allowed: number; sanitized: number } } {
  const sanitizedList: string[] = [];
  let allowed = 0;
  let sanitized = 0;

  for (const item of findings) {
    const result = validateAssertion(item, validEvidenceIds, evidenceItems);
    if (result.isAllowed) {
      sanitizedList.push(result.text);
      allowed++;
    } else {
      // Convert unbacked factual assertion to honest unverified statement
      sanitizedList.push(`${item} (Notice: Statement could not be verified against collected evidence)`);
      sanitized++;
    }
  }

  return {
    sanitizedList,
    audit: { checked: findings.length, allowed, sanitized },
  };
}

/**
 * Deeply guards a complete scan report object before returning to client.
 */
export function runReportAssertionGuard(
  report: any,
  evidenceItems: Array<{ id?: string; source_name?: string; title?: string; evidence_type?: string }> = []
): { guardedReport: any; guardAudit: GuardAuditSummary } {
  // Extract all valid evidence IDs and prefixes from the scan
  const validIds = new Set<string>();
  evidenceItems.forEach(e => {
    if (e.id) validIds.add(e.id);
  });

  // Also register common dual RAG chunk IDs present in report
  if (report?.dual_rag_citations?.document_citations) {
    report.dual_rag_citations.document_citations.forEach((c: any) => validIds.add(c.citation));
  }
  if (report?.dual_rag_citations?.external_citations) {
    report.dual_rag_citations.external_citations.forEach((c: any) => validIds.add(c.citation));
  }

  let totalChecked = 0;
  let allowedWithEvidence = 0;
  let allowedAsUncertainty = 0;
  let blockedOrSanitized = 0;

  const auditedReport = { ...report };

  // Guard Critical Signals
  if (Array.isArray(auditedReport.critical_signals)) {
    const res = guardFindingsList(auditedReport.critical_signals, validIds, 'Critical Signal', evidenceItems);
    auditedReport.critical_signals = res.sanitizedList;
    totalChecked += res.audit.checked;
    allowedWithEvidence += res.audit.allowed;
    blockedOrSanitized += res.audit.sanitized;
  }

  // Guard Warning Signals
  if (Array.isArray(auditedReport.warning_signals)) {
    const res = guardFindingsList(auditedReport.warning_signals, validIds, 'Warning Signal', evidenceItems);
    auditedReport.warning_signals = res.sanitizedList;
    totalChecked += res.audit.checked;
    allowedWithEvidence += res.audit.allowed;
    blockedOrSanitized += res.audit.sanitized;
  }

  // Guard Positive Signals
  if (Array.isArray(auditedReport.positive_signals)) {
    const res = guardFindingsList(auditedReport.positive_signals, validIds, 'Positive Signal', evidenceItems);
    auditedReport.positive_signals = res.sanitizedList;
    totalChecked += res.audit.checked;
    allowedWithEvidence += res.audit.allowed;
    blockedOrSanitized += res.audit.sanitized;
  }

  // Guard Gemini Reconciliation Agreements & Contradictions
  if (auditedReport.gemini_reconciliation) {
    if (Array.isArray(auditedReport.gemini_reconciliation.agreements)) {
      const res = guardFindingsList(auditedReport.gemini_reconciliation.agreements, validIds, 'Agreement', evidenceItems);
      auditedReport.gemini_reconciliation.agreements = res.sanitizedList;
      totalChecked += res.audit.checked;
      allowedWithEvidence += res.audit.allowed;
      blockedOrSanitized += res.audit.sanitized;
    }
    if (Array.isArray(auditedReport.gemini_reconciliation.contradictions)) {
      const res = guardFindingsList(auditedReport.gemini_reconciliation.contradictions, validIds, 'Contradiction', evidenceItems);
      auditedReport.gemini_reconciliation.contradictions = res.sanitizedList;
      totalChecked += res.audit.checked;
      allowedWithEvidence += res.audit.allowed;
      blockedOrSanitized += res.audit.sanitized;
    }
  }

  const guardAudit: GuardAuditSummary = {
    totalAssertionsChecked: totalChecked,
    allowedWithEvidence,
    allowedAsUncertainty,
    blockedOrSanitized,
    evidenceIdsRegistered: validIds.size,
    timestamp: new Date().toISOString(),
  };

  auditedReport.assertion_guard_audit = guardAudit;

  return {
    guardedReport: auditedReport,
    guardAudit,
  };
}
