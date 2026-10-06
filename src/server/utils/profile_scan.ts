import fs from 'fs';
import { processDocument } from '../services/documentService';
import { verifyCompanyRegistry } from '../services/companyRegistryService';
import { analyzeDomain } from '../services/domainService';
import { analyzeRecruiterEmail } from '../services/emailService';
import { checkThreatIndicators } from '../services/threatService';
import { searchPublicExperiences } from '../services/publicExperienceService';
import { predictJobOfferRisk } from '../ml/fraudClassifier';
import { calculateDeterministicScore, calculateEvidenceCompleteness } from '../services/scoringService';
import { compileFullReport } from '../services/reportService';
import { getActiveAIProvider } from '../services/aiProvider';
import { buildEntityGraph } from '../services/entityGraphService';

async function profile() {
  const t0 = Date.now();
  console.log('[1/10] Reading file...');
  const buf = fs.readFileSync('C:/Users/Priya/.gemini/antigravity/brain/110b1791-400d-4384-b7fa-03248cb226df/.user_uploaded/media_1786998164644.jpg');
  
  console.log('[2/10] Processing Document & OCR...');
  const tDoc = Date.now();
  const docResult = await processDocument(buf, 'indigo_offer.jpg', 'image/jpeg');
  console.log(` -> Document processed in ${Date.now() - tDoc}ms. Detected Co: ${docResult.detected_company_name}`);

  const targetCompany = docResult.detected_company_name || 'IndiGo';
  const targetDomain = 'goindigohr.in';
  const targetEmail = 'recruit@goindigohr.in';

  console.log('[3/10] Parallel Lookups...');
  const tLookups = Date.now();
  const [mcaResult, domResult, threatResult, communityResult] = await Promise.all([
    verifyCompanyRegistry(targetCompany),
    analyzeDomain(targetDomain),
    checkThreatIndicators([targetCompany, targetDomain, targetEmail]),
    searchPublicExperiences({ companyName: targetCompany, domain: targetDomain, recruiterEmail: targetEmail }),
  ]);
  console.log(` -> Lookups completed in ${Date.now() - tLookups}ms. Lookalike: ${domResult.data.lookalike_detected}`);

  console.log('[4/10] Recruiter Email Analysis...');
  const recResult = analyzeRecruiterEmail(targetEmail, 'goindigo.in', targetCompany);

  console.log('[5/10] ML Model Inference...');
  const mlPrediction = predictJobOfferRisk({
    text: docResult.extracted_text,
    hasCompanyProfile: true,
    hasCompanyLogo: false,
    telecommuting: false,
  });
  console.log(` -> ML Fraud Prob: ${(mlPrediction.fraudProbability * 100).toFixed(1)}%`);

  console.log('[6/10] Deterministic Scoring...');
  const evidence = [
    ...docResult.evidence,
    ...mcaResult.evidence,
    ...domResult.evidence,
    ...recResult.evidence,
    ...(threatResult ? threatResult.evidence : []),
    ...communityResult.evidence,
  ];

  const completeness = calculateEvidenceCompleteness({
    companyData: undefined,
    domainData: domResult.data,
    recruiterData: recResult.data,
    documentData: docResult,
    threatData: threatResult ? threatResult.data : undefined,
    mlPrediction,
    communityData: communityResult,
    evidence,
  });

  const scoreResult = calculateDeterministicScore({
    companyData: undefined,
    domainData: domResult.data,
    recruiterData: recResult.data,
    documentData: docResult,
    threatData: threatResult ? threatResult.data : undefined,
    mlPrediction,
    communityData: communityResult,
    evidence,
  });

  console.log(` -> Final Trust Score: ${scoreResult.trust_score}/100 | Risk: ${scoreResult.risk_level} | Verdict: ${scoreResult.verdict}`);

  console.log('[7/10] Synthesis & Graph...');
  const aiProvider = await getActiveAIProvider();
  const aiSynthesis = await aiProvider.generateSynthesis({
    entityName: targetCompany,
    entityType: 'document',
    trustScore: scoreResult.trust_score,
    confidence: scoreResult.confidence_score,
    riskLevel: scoreResult.risk_level,
    verdict: scoreResult.verdict,
    evidence,
    rulesTriggered: scoreResult.rules_triggered,
    mlEvaluation: mlPrediction as any,
    untrustedUserText: docResult.extracted_text,
  });

  const entityGraph = buildEntityGraph({
    companyName: targetCompany,
    domain: targetDomain,
    recruiterEmail: targetEmail,
    claims: [],
    chunks: [],
  });

  console.log(`[10/10] COMPLETE in ${Date.now() - t0}ms!`);
  process.exit(0);
}

profile().catch(console.error);
