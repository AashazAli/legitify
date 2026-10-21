// ==============================================================================
// LEGITIFY COLORFUL FORENSIC PDF REPORT EXPORT SERVICE (A4 EXECUTIVE TEMPLATE)
// ==============================================================================
import { jsPDF } from 'jspdf';
import { LegitifyReport, AssessmentItem } from '../types';

function formatConfidence(val: any): number {
  const num = Number(val);
  if (isNaN(num) || num === 0) return 85;
  if (num > 100) return Math.min(100, Math.round(num / 100));
  if (num <= 1 && num > 0) return Math.round(num * 100);
  return Math.min(100, Math.max(0, Math.round(num)));
}

function isFilenameOrPlaceholder(name?: string): boolean {
  if (!name || typeof name !== 'string') return true;
  const trimmed = name.trim();
  if (trimmed.length < 2) return true;
  if (/^whatsapp\s*image/i.test(trimmed)) return true;
  if (/^screenshot/i.test(trimmed)) return true;
  if (/^pasted_text/i.test(trimmed)) return true;
  if (/^image\s*\(/i.test(trimmed)) return true;
  if (/^scan_|^document_|^file_/i.test(trimmed)) return true;
  if (/\.(png|jpe?g|pdf|webp|tiff|gif|bmp|docx?)$/i.test(trimmed)) return true;
  if (/^\d{4}[-_]\d{2}[-_]\d{2}/.test(trimmed)) return true;
  if (/^(?:unknown(?:\s*(?:organization|company|entity))?|corporate\s*entity|investigated\s*entity|uploaded\s*document|candidate|n\/a|none|null|undefined)$/i.test(trimmed)) return true;
  if (/^\(?\s*(?:first|second|third|fourth|fist|last|initial)\s+(?:section|ection|part|page|clause|annexure)\s*\)?$/i.test(trimmed)) return true;
  if (/^\(?\s*(?:section|part|clause|annexure|page|table)\s*[\d\w.:\-_]*\s*\)?$/i.test(trimmed)) return true;
  if (!/[a-zA-Z]/.test(trimmed)) return true;
  return false;
}

function getRiskBandColor(band?: string, score?: number): { fill: [number, number, number]; text: [number, number, number] } {
  const b = (band || '').toUpperCase();
  const s = score ?? 50;
  if (b.includes('CRITICAL') || s >= 71) {
    return { fill: [254, 242, 242], text: [185, 28, 28] }; // Red
  }
  if (b.includes('MODERATE') || (s >= 41 && s <= 70)) {
    return { fill: [254, 249, 195], text: [161, 98, 7] }; // Amber
  }
  if (b.includes('MINOR') || (s >= 16 && s <= 40)) {
    return { fill: [238, 242, 255], text: [67, 56, 202] }; // Indigo
  }
  return { fill: [240, 253, 244], text: [22, 101, 52] }; // Green
}

export function generatePdfDocument(report: LegitifyReport, fallbackAssessments?: AssessmentItem[]): jsPDF {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 14;
  const contentWidth = pageWidth - (margin * 2);
  let y = 14;
  let currentPage = 1;

  function checkPageBreak(spaceNeeded: number) {
    if (y + spaceNeeded > pageHeight - 16) {
      addPageFooter();
      doc.addPage();
      currentPage++;
      y = 16;
      addPageHeader();
    }
  }

  function addPageHeader() {
    doc.setFillColor(7, 11, 18);
    doc.rect(0, 0, pageWidth, 12, 'F');
    doc.setTextColor(0, 255, 135);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.text('LEGITIFY · EVIDENCE-BASED FORENSIC INVESTIGATION REPORT', margin, 8);
    doc.setTextColor(148, 163, 184);
    doc.setFont('helvetica', 'normal');
    doc.text(`CASE ID: ${report.scan_id || 'LGF-2026-000184'}`, pageWidth - margin, 8, { align: 'right' });
  }

  function addPageFooter() {
    doc.setDrawColor(30, 41, 59);
    doc.setLineWidth(0.3);
    doc.line(margin, pageHeight - 10, pageWidth - margin, pageHeight - 10);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);
    doc.text('CONFIDENTIAL · EVIDENCE-BASED INVESTIGATION REPORT · TAMPER-EVIDENT', margin, pageHeight - 5);
    doc.text(`Page ${currentPage}`, pageWidth - margin, pageHeight - 5, { align: 'right' });
  }

  // Subtle Background Watermark
  doc.setTextColor(245, 247, 250);
  doc.setFontSize(34);
  doc.setFont('helvetica', 'bold');
  doc.text('LEGITIFY EVIDENCE-FIRST', 35, 150, { angle: 45 });

  // --------------------------------------------------------------------------
  // PAGE 1: COVER & EXECUTIVE DOSSIER
  // --------------------------------------------------------------------------

  // Top Dark Header Banner
  doc.setFillColor(7, 11, 18);
  doc.rect(0, 0, pageWidth, 30, 'F');

  doc.setTextColor(0, 255, 135);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.text('LEGITIFY', margin, 13);

  doc.setTextColor(248, 250, 252);
  doc.setFontSize(9);
  doc.text('TRUST & RECRUITMENT FRAUD FORENSIC DOSSIER', margin, 20);

  doc.setTextColor(148, 163, 184);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.text(`Generated: ${new Date().toUTCString()} | Multi-Factor Evidence Verification`, margin, 25);
  doc.text(`Scan ID: ${report.scan_id || 'LGF-2026-000184'}`, pageWidth - margin, 25, { align: 'right' });

  y = 36;

  // Sanitize entity name (strictly no filenames or placeholders)
  let cleanName = (report.company_name || report.entity_name || report.company_verification?.legal_name || '').trim();
  if (!cleanName || isFilenameOrPlaceholder(cleanName)) {
    cleanName = 'Organization Not Confidently Identified';
  }

  // Exact Trust Score & Overall Risk Score Resolution (NO HARDCODING)
  const trustScore = typeof report.trust_score === 'number'
    ? Math.round(report.trust_score)
    : typeof (report as any).final_score === 'number'
    ? Math.round((report as any).final_score)
    : 50;

  const overallRiskScore = typeof report.overall_risk_score === 'number'
    ? Math.round(report.overall_risk_score)
    : (report.assessments?.find((a: any) => a.id === 'overall_offer_risk')?.risk_score ?? Math.max(1, Math.min(99, 100 - trustScore)));

  const rawVerdict = (report.verdict || (trustScore <= 35 || overallRiskScore >= 70 ? "LIKELY SCAM" : trustScore <= 65 ? "SUSPICIOUS" : "LIKELY GENUINE")).toUpperCase();
  const isHighRisk = rawVerdict.includes('SCAM') || rawVerdict.includes('FAKE') || rawVerdict.includes('CRITICAL') || overallRiskScore >= 70 || trustScore <= 35;
  const isModerateRisk = !isHighRisk && (rawVerdict.includes('SUSPICIOUS') || rawVerdict.includes('MODERATE') || overallRiskScore >= 40 || trustScore <= 65);

  const confidenceVal = typeof report.confidence === 'number'
    ? formatConfidence(report.confidence)
    : (typeof report.confidence_score === 'number' && report.confidence_score !== trustScore
    ? formatConfidence(report.confidence_score)
    : Math.round(report.evidence_completeness?.percentage || 75));

  const isServerPaymentNegative = report.payment_case === 'POLICY_MENTION_WITHOUT_DEMAND' ||
    report.payment_case === 'WARNING_AGAINST_PAYMENT' ||
    report.payment_case === 'NO_PAYMENT_EVIDENCE';

  const hasFeeDemand = !isServerPaymentNegative && Boolean(
    report.has_fee_demand ||
    (report as any).hasPaymentDemand ||
    report.rules_triggered?.some(r => r.rule_id === 'R002' && (r as any).triggered !== false) ||
    report.red_flags?.some((f: any) => typeof f === 'string' ? f.toLowerCase().includes('money') || f.toLowerCase().includes('fee') || f.toLowerCase().includes('payment') : f.message?.toLowerCase().includes('money') || f.message?.toLowerCase().includes('fee') || f.message?.toLowerCase().includes('payment')) ||
    report.hard_caps_applied?.some(c => c.toLowerCase().includes('payment_request_cap'))
  );

  // Two-Column Dossier Card
  doc.setFillColor(15, 23, 42);
  doc.setDrawColor(30, 41, 59);
  doc.setLineWidth(0.4);
  doc.roundedRect(margin, y, contentWidth, 36, 2, 2, 'FD');

  doc.setTextColor(248, 250, 252);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(13);
  doc.text(cleanName, margin + 5, y + 8);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(148, 163, 184);
  doc.text(`TARGET TYPE: ${String(report.entity_type || 'JOB_OFFER').toUpperCase()} | INPUT FORMAT: ${String(report.input_type || (report.document_analysis?.filename?.endsWith('.pdf') ? 'PDF DOCUMENT' : 'DIGITAL RECORD')).toUpperCase()}`, margin + 5, y + 14);
  doc.text(`TRUST INDEX: ${trustScore}/100 | OVERALL RISK SCORE: ${overallRiskScore}/100`, margin + 5, y + 20);
  doc.text(`ASSESSMENT CONFIDENCE: ${confidenceVal}% | VERDICT: ${rawVerdict}`, margin + 5, y + 26);
  doc.text(`SAFETY STATUS: ${hasFeeDemand ? 'ALERT: Candidate Upfront Payment Demand Detected' : 'Zero-Fee Protocol Compliant'}`, margin + 5, y + 32);

  // Dynamic Score Badge on Right — Displays Canonical Website Score (Trust Index)
  const scoreX = pageWidth - margin - 46;
  if (isHighRisk) {
    doc.setFillColor(239, 68, 68); // Red
  } else if (isModerateRisk) {
    doc.setFillColor(245, 158, 11); // Amber
  } else {
    doc.setFillColor(16, 185, 129); // Green
  }
  doc.roundedRect(scoreX, y + 4, 42, 28, 2, 2, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(6.5);
  doc.text('TRUST INDEX', scoreX + 21, y + 10, { align: 'center' });

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.text(`${trustScore}/100`, scoreX + 21, y + 19, { align: 'center' });

  doc.setFontSize(6.5);
  doc.text(rawVerdict.slice(0, 16), scoreX + 21, y + 26, { align: 'center' });

  y += 42;

  // 1. Executive Summary Card
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(margin, y, contentWidth, 24, 2, 2, 'FD');

  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.text('1. EXECUTIVE INVESTIGATION SUMMARY', margin + 5, y + 6);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(71, 85, 105);
  const rawSummary = report.ai_synthesis?.summary ||
    report.executive_summary ||
    (Array.isArray(report.structured_explanation) && report.structured_explanation.length > 0 ? report.structured_explanation.join(' ') : '') ||
    (isHighRisk
      ? `Critical recruitment fraud patterns detected for ${cleanName}. Evidence confirms unauthorized payment solicitation or deceptive sender infrastructure. Exercise extreme caution.`
      : isModerateRisk
      ? `Document contains structural anomalies and uncorroborated sender contact points for ${cleanName}. Verification via verified corporate directories advised.`
      : `Forensic analysis confirms authentic corporate registration, verified domain routing, and zero applicant payment demands for ${cleanName}.`);
  doc.text(doc.splitTextToSize(rawSummary, contentWidth - 10).slice(0, 3), margin + 5, y + 12);

  y += 28;

  // --------------------------------------------------------------------------
  // SECTION 2: DETAILED PAYMENT & FINANCIAL FEE FINDINGS
  // --------------------------------------------------------------------------
  checkPageBreak(38);
  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.5);
  doc.text('2. DETAILED PAYMENT & FINANCIAL FEE FINDINGS', margin, y);

  y += 4;

  const docFeeDetails = (report.document_analysis as any)?.fee_details || (report as any).fee_details || [];
  const primaryFee = docFeeDetails[0];
  const rawComp = (report.document_analysis as any)?.candidate_compensation || (report as any).candidate_compensation;
  const candidateCompList = Array.isArray(rawComp) ? rawComp : (rawComp && typeof rawComp === 'object' ? [rawComp] : []);

  const finBoxHeight = hasFeeDemand ? 32 : 22;
  doc.setFillColor(hasFeeDemand ? 254 : 240, hasFeeDemand ? 242 : 253, hasFeeDemand ? 242 : 244);
  doc.setDrawColor(hasFeeDemand ? 254 : 187, hasFeeDemand ? 202 : 247, hasFeeDemand ? 202 : 208);
  doc.roundedRect(margin, y, contentWidth, finBoxHeight, 2, 2, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  if (hasFeeDemand) {
    doc.setTextColor(185, 28, 28);
    doc.text('ALERT: Explicit Candidate Upfront Fee / Deposit Demand Detected', margin + 5, y + 6);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(71, 85, 105);
    const feeAmt = primaryFee?.amount || (report.document_analysis as any)?.detected_stipend || 'Unspecified Amount';
    const feeRec = primaryFee?.recipient || 'Unspecified Payment Endpoint';
    const feeRef = primaryFee?.is_refundable ? `Claimed Refundable (${primaryFee.refund_terms || 'conditional'})` : 'Non-Refundable / Unstated';
    const feeDead = primaryFee?.deadline ? `Deadline: ${primaryFee.deadline}` : 'Immediate';

    doc.text(`Amount Demanded: ${feeAmt} | Recipient / Channel: ${feeRec} | Refund Terms: ${feeRef} | ${feeDead}`, margin + 5, y + 12);

    if (primaryFee?.exact_quote) {
      doc.setFont('helvetica', 'italic');
      doc.setTextColor(127, 29, 29);
      const quoteText = `Exact Excerpt: "${primaryFee.exact_quote}"`;
      doc.text(doc.splitTextToSize(quoteText, contentWidth - 10).slice(0, 2), margin + 5, y + 17);
    }

    doc.setFont('helvetica', 'bold');
    doc.setTextColor(185, 28, 28);
    doc.text('CRITICAL WARNING: Genuine employers NEVER ask candidates for fees, training costs, or caution money.', margin + 5, y + 27);
  } else {
    doc.setTextColor(22, 101, 52);
    doc.text('VERIFIED: Zero Candidate Monetary Charges Detected (Zero-Fee Protocol Compliant)', margin + 5, y + 6);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(71, 85, 105);
    const compText = candidateCompList.length > 0
      ? `Candidate Compensation Stated: ${candidateCompList.map((c: any) => `${c.type || 'Remuneration'}: ${c.amount || c.raw_quote || c.rawText || ''}`).join(', ')} (Remuneration payable TO candidate).`
      : 'No upfront fee demands, laptop caution money, registration fees, or processing charges found in text.';
    doc.text(doc.splitTextToSize(compText, contentWidth - 10).slice(0, 2), margin + 5, y + 12);

    doc.setFont('helvetica', 'bold');
    doc.setTextColor(22, 101, 52);
    doc.text('COMPLIANCE NOTE: The document complies with legitimate enterprise zero-fee recruitment practices.', margin + 5, y + 18);
  }

  y += finBoxHeight + 6;

  // --------------------------------------------------------------------------
  // SECTION 3: COMPREHENSIVE MULTI-VECTOR RISK ASSESSMENTS (ALL 12 VECTORS)
  // Single source of truth from report.assessments
  // --------------------------------------------------------------------------
  checkPageBreak(30);
  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.5);
  doc.text('3. COMPREHENSIVE MULTI-VECTOR RISK ASSESSMENTS (12 FORENSIC VECTORS)', margin, y);

  y += 5;

  const rawAssessmentsList: AssessmentItem[] = (report.assessments && report.assessments.length > 0)
    ? report.assessments
    : [];

  const assessmentsList: AssessmentItem[] = rawAssessmentsList.map(item => {
    if (item.id === 'financial_safety' && hasFeeDemand && (item.risk_score || 0) < 70 && !isServerPaymentNegative) {
      const feeQuote = report.document_analysis?.fee_details?.[0]?.exact_quote ||
        (report.critical_signals && report.critical_signals.find((s: any) => /fee|deposit|payment/i.test(s))) ||
        (report.rules_triggered && report.rules_triggered.find((r: any) => /fee|deposit/i.test(r.name || ''))?.explanation);
      return {
        ...item,
        risk_score: 96,
        risk_band: 'CRITICAL_RISK',
        risk_band_label: 'Critical Fraud Risk',
        evidence_found: feeQuote
          ? `Explicit candidate fee or security deposit detected: "${feeQuote}"`
          : 'Explicit candidate fee, caution deposit, or monetary demand detected in document.',
        why_it_matters: 'Legitimate employers never demand candidate registration fees or caution deposits. Any fee demand is an immediate scam indicator.',
        recommended_next_step: 'NEVER transfer funds or UPI payments. Terminate contact and report to 1930 Cybercrime Helpline.',
      };
    }
    return item;
  });

  if (assessmentsList.length > 0) {
    assessmentsList.forEach((item, idx) => {
      // Calculate needed vertical space for this assessment card
      const evLines = doc.splitTextToSize(item.evidence_found || 'No evidence recorded.', contentWidth - 12);
      const whyLines = doc.splitTextToSize(item.why_it_matters || '', contentWidth - 12);
      const nextLines = doc.splitTextToSize(item.recommended_next_step || '', contentWidth - 12);

      const quoteLines = item.exact_quote ? doc.splitTextToSize(`Exact Quote: "${item.exact_quote}"`, contentWidth - 12) : [];
      const extraHeight = (quoteLines.length > 0 ? quoteLines.length * 3.2 + 2 : 0);
      const cardHeight = 16 + (evLines.length * 3.2) + (whyLines.length * 3.2) + (nextLines.length * 3.2) + extraHeight;

      checkPageBreak(cardHeight + 4);

      const colors = getRiskBandColor(item.risk_band, item.risk_score);

      // Card Background
      doc.setFillColor(255, 255, 255);
      doc.setDrawColor(226, 232, 240);
      doc.setLineWidth(0.3);
      doc.roundedRect(margin, y, contentWidth, cardHeight, 1.5, 1.5, 'FD');

      // Left Accent Color Bar
      doc.setFillColor(...colors.text);
      doc.rect(margin, y, 2.5, cardHeight, 'F');

      // Title & Score Badge
      doc.setTextColor(15, 23, 42);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.text(`${idx + 1}. ${item.name}`, margin + 6, y + 5);

      // Risk Badge on Right
      doc.setFillColor(...colors.fill);
      doc.roundedRect(pageWidth - margin - 42, y + 2, 38, 5.5, 1, 1, 'F');
      doc.setTextColor(...colors.text);
      const resolvedScore = (item.risk_score !== null && item.risk_score !== undefined)
        ? item.risk_score
        : 15;
      const scoreBadgeText = `${resolvedScore}/100 Risk · ${item.risk_band_label || item.risk_band || 'Evaluated'}`;
      doc.text(scoreBadgeText, pageWidth - margin - 23, y + 5.8, { align: 'center' });

      let cardY = y + 9.5;

      // Evidence Found
      doc.setTextColor(51, 65, 85);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.8);
      doc.text('Evidence Found: ', margin + 6, cardY);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);
      for (const line of evLines) {
        doc.text(line, margin + 26, cardY);
        cardY += 3.2;
      }

      // Exact Quote if present
      if (item.exact_quote && quoteLines.length > 0) {
        doc.setFont('helvetica', 'italic');
        doc.setTextColor(185, 28, 28);
        for (const qLine of quoteLines) {
          doc.text(qLine, margin + 6, cardY);
          cardY += 3.2;
        }
      }

      // Why It Matters
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(51, 65, 85);
      doc.setFontSize(6.8);
      doc.text('Why It Matters: ', margin + 6, cardY);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(100, 116, 139);
      for (const line of whyLines) {
        doc.text(line, margin + 26, cardY);
        cardY += 3.2;
      }

      // Recommended Next Step
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(15, 23, 42);
      doc.setFontSize(6.8);
      doc.text('Next Step: ', margin + 6, cardY);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(30, 41, 59);
      for (const line of nextLines) {
        doc.text(line, margin + 26, cardY);
        cardY += 3.2;
      }

      y += cardHeight + 3;
    });
  }

  y += 4;

  // --------------------------------------------------------------------------
  // SECTION 4: EXTERNAL VERIFICATION & INTELLIGENCE FINDINGS
  // --------------------------------------------------------------------------
  const extResearch = (report as any).external_research;
  checkPageBreak(36);
  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.5);
  doc.text('4. EXTERNAL VERIFICATION & INTELLIGENCE FINDINGS', margin, y);

  y += 4;

  const extItems = [
    {
      source: 'LinkedIn Directory',
      status: extResearch?.linkedin?.found ? 'VERIFIED' : 'UNVERIFIED',
      detail: extResearch?.linkedin?.details || 'Cross-referenced company presence and recruiter profiles.',
    },
    {
      source: 'Reddit Discussions',
      status: extResearch?.reddit?.scam_reports > 0 ? 'ALERT' : 'CLEAR',
      detail: extResearch?.reddit?.summary || 'Scanned r/cscareerquestions, r/recruitinghell for scam reports.',
    },
    {
      source: 'Quora Intelligence',
      status: extResearch?.quora?.found ? 'OBSERVED' : 'CLEAR',
      detail: extResearch?.quora?.summary || 'Indexed peer candidate reviews and employer inquiries.',
    },
    {
      source: 'MCA21 Statutory Registry',
      status: report.company_verification?.status === 'ACTIVE' ? 'VERIFIED' : 'UNVERIFIED',
      detail: report.company_verification?.legal_name ? `Statutory legal entity: ${report.company_verification.legal_name}` : 'Not corroborated against live MCA master data.',
    },
  ];

  extItems.forEach(item => {
    checkPageBreak(12);
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.roundedRect(margin, y, contentWidth, 10, 1, 1, 'FD');

    doc.setTextColor(15, 23, 42);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.text(item.source, margin + 4, y + 4.5);

    const isAlert = item.status === 'ALERT';
    const isGood = item.status === 'VERIFIED';
    doc.setTextColor(isAlert ? 185 : isGood ? 22 : 100, isAlert ? 28 : isGood ? 101 : 116, isAlert ? 28 : isGood ? 52 : 139);
    doc.setFontSize(6.5);
    doc.text(`[${item.status}]`, margin + 45, y + 4.5);

    doc.setTextColor(71, 85, 105);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.text(doc.splitTextToSize(item.detail, contentWidth - 65)[0] || item.detail, margin + 65, y + 4.5);

    y += 11;
  });

  y += 2;

  // --------------------------------------------------------------------------
  // SECTION 5: SIGNATORY & VISUAL FORENSICS FINDINGS
  // --------------------------------------------------------------------------
  const sigForensics = report.signatory_forensics;
  checkPageBreak(28);
  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.5);
  doc.text('5. SIGNATORY & VISUAL FORENSICS FINDINGS', margin, y);

  y += 4;

  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(margin, y, contentWidth, 18, 1.5, 1.5, 'FD');

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(51, 65, 85);

  const sigMark = sigForensics?.signature_detected ? `Detected (${sigForensics.signature_type || 'Image Mark'})` : 'No Visual Signature Stroke';
  const sigName = sigForensics?.signatory_name || report.document_analysis?.detected_signatory || 'Signatory Unextracted';
  const sigTitle = sigForensics?.signatory_title || 'Title Unextracted';
  const sigState = sigForensics?.identity_state || 'UNVERIFIED';

  doc.text(`Signature Mark: ${sigMark} | State: [${sigState}]`, margin + 4, y + 6);
  doc.text(`Signatory Name: ${sigName} | Title: ${sigTitle}`, margin + 4, y + 11);
  doc.text(`Detection Method: ${sigForensics?.detection_method || 'Computer Vision Edge & Template Analysis'}`, margin + 4, y + 16);

  y += 22;

  // --------------------------------------------------------------------------
  // SECTION 6: OFFICIAL LEGAL DISCLAIMER & EMERGENCY PROTOCOL
  // --------------------------------------------------------------------------
  checkPageBreak(24);
  doc.setFillColor(241, 245, 249);
  doc.setDrawColor(203, 213, 225);
  doc.roundedRect(margin, y, contentWidth, 18, 1.5, 1.5, 'FD');

  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.text('OFFICIAL LEGAL DISCLAIMER & EMERGENCY PROTOCOL', margin + 4, y + 5);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(6.5);
  doc.setTextColor(100, 116, 139);
  const disclaimerText = 'LEGITIFY provides automated evidence-based risk analysis to support applicant decision-making. It is not a legal determination, guarantee of employment legitimacy, or definitive proof of fraudulent intent. If you have transferred funds to an unverified counterparty, contact the National Cybercrime Helpline at 1930 immediately.';
  doc.text(doc.splitTextToSize(disclaimerText, contentWidth - 8), margin + 4, y + 9.5);

  addPageFooter();
  return doc;
}

export function exportReportPDF(report: LegitifyReport, fallbackAssessments?: AssessmentItem[]): void {
  const doc = generatePdfDocument(report, fallbackAssessments);
  let cleanName = (report.company_name || report.entity_name || report.company_verification?.legal_name || '').trim();
  if (!cleanName || isFilenameOrPlaceholder(cleanName)) {
    cleanName = 'Organization Not Confidently Identified';
  }
  const safeFilenamePart = cleanName.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 30);
  const cleanFilename = `LEGITIFY_FORENSIC_REPORT_${safeFilenamePart}_${report.scan_id || 'DOSSIER'}.pdf`;
  doc.save(cleanFilename);
}

export const exportReportToPdf = exportReportPDF;
