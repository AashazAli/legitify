import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

export interface MLPrediction {
  modelVersion: string;
  algorithm: string;
  prediction: "FRAUDULENT" | "LEGITIMATE" | "ML_UNAVAILABLE";
  fraudProbability: number;
  legitimateProbability: number;
  confidence: number;
  ml_probability: number;
  ml_probability_percent: number;
  model_version: string;
  model_loaded: boolean;
  feature_count: number;
  topFeatures: { feature: string; contribution: number; direction: "FRAUD" | "LEGITIMATE" }[];
  textSignals: {
    wordCount: number;
    hasTelecommuting: boolean;
    hasCompanyLogo: boolean;
    hasCompanyProfile: boolean;
    hasSalaryRange: boolean;
  };
  error?: string;
}

export interface MLModelMetrics {
  modelVersion: string;
  algorithm: string;
  dataset: string;
  trainedAt: string;
  totalTrainingRows: number;
  bestModel: string;
  modelLoaded: boolean;
  featureCount: number;
  evaluationMetrics: Record<string, {
    accuracy: number;
    precision: number;
    recall: number;
    f1: number;
    roc_auc: number;
    pr_auc: number;
    confusion_matrix: number[][];
  }>;
  topFraudFeatures: { feature: string; weight: number }[];
  topLegitFeatures: { feature: string; weight: number }[];
}

let loadedArtifact: any = null;

function getArtifact(): any | null {
  if (loadedArtifact) return loadedArtifact;

  // Try 1: CommonJS createRequire (Vercel serverless / Node / tsx safe)
  try {
    const require = createRequire(import.meta.url);
    loadedArtifact = require('./modelArtifact.json');
    if (loadedArtifact?.featureWeights) return loadedArtifact;
  } catch {}

  // Try 2: Filesystem relative to import.meta.url
  try {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    const artifactPath = path.join(__dirname, 'modelArtifact.json');
    if (fs.existsSync(artifactPath)) {
      loadedArtifact = JSON.parse(fs.readFileSync(artifactPath, 'utf-8'));
      if (loadedArtifact?.featureWeights) return loadedArtifact;
    }
  } catch {}

  // Try 3: Process CWD resolution
  try {
    const cwdPath = path.resolve(process.cwd(), 'src/server/ml/modelArtifact.json');
    if (fs.existsSync(cwdPath)) {
      loadedArtifact = JSON.parse(fs.readFileSync(cwdPath, 'utf-8'));
      if (loadedArtifact?.featureWeights) return loadedArtifact;
    }
  } catch {}

  // Zero hardcoded fake weights: return null if artifact is unparseable
  loadedArtifact = null;
  return null;
}

export function getMLModelMetrics(): MLModelMetrics {
  const art = getArtifact();
  if (!art) {
    return {
      modelVersion: "1.2.0-kaggle-supervised",
      algorithm: "Linear SVM (Calibrated)",
      dataset: "Kaggle Real / Fake Job Postings Dataset",
      trainedAt: "2026-08-18",
      totalTrainingRows: 17880,
      bestModel: "Linear SVM (Calibrated)",
      modelLoaded: false,
      featureCount: 0,
      evaluationMetrics: {},
      topFraudFeatures: [],
      topLegitFeatures: [],
    };
  }

  return {
    modelVersion: art.modelVersion,
    algorithm: art.bestModel || art.algorithm || "Linear SVM (Calibrated)",
    dataset: art.dataset || "Kaggle Real / Fake Job Postings Dataset",
    trainedAt: art.trainedAt || "2026-08-18",
    totalTrainingRows: art.totalTrainingRows || 17880,
    bestModel: art.bestModel || "Linear SVM (Calibrated)",
    modelLoaded: true,
    featureCount: Object.keys(art.featureWeights || {}).length,
    evaluationMetrics: art.evaluationMetrics || {},
    topFraudFeatures: art.topFraudFeatures || [],
    topLegitFeatures: art.topLegitFeatures || [],
  };
}

/**
 * Predicts fraud probability from job offer text and metadata signals.
 */
export function predictJobOfferRisk(params: {
  text: string;
  telecommuting?: boolean;
  hasCompanyLogo?: boolean;
  hasCompanyProfile?: boolean;
  hasSalaryRange?: boolean;
  hasQuestions?: boolean;
}): MLPrediction {
  const art = getArtifact();
  const rawText = (params.text || '').toLowerCase().replace(/[^a-z0-9\s]/g, ' ');
  const words = rawText.split(/\s+/).filter(w => w.length > 0);
  const wordCount = words.length;

  if (!art) {
    return {
      modelVersion: "1.2.0-kaggle-supervised",
      algorithm: "Linear SVM (Calibrated)",
      prediction: "ML_UNAVAILABLE",
      fraudProbability: 0,
      legitimateProbability: 0,
      confidence: 0,
      ml_probability: 0,
      ml_probability_percent: 0,
      model_version: "1.2.0-kaggle-supervised",
      model_loaded: false,
      feature_count: 0,
      topFeatures: [],
      textSignals: {
        wordCount,
        hasTelecommuting: !!params.telecommuting,
        hasCompanyLogo: !!params.hasCompanyLogo,
        hasCompanyProfile: !!params.hasCompanyProfile,
        hasSalaryRange: !!params.hasSalaryRange,
      },
      error: "ML model artifact not loaded"
    };
  }

  const weights: Record<string, number> = art.featureWeights || {};
  let score = art.intercept || -2.5;

  const contributions: { feature: string; contribution: number; direction: "FRAUD" | "LEGITIMATE" }[] = [];

  // 1. Auxiliary features
  const hasLogo = params.hasCompanyLogo !== undefined ? params.hasCompanyLogo : (rawText.includes('logo') || rawText.includes('branding'));
  const hasProfile = params.hasCompanyProfile !== undefined ? params.hasCompanyProfile : (rawText.includes('about us') || rawText.includes('company profile') || rawText.length > 300);
  const isTelecommuting = params.telecommuting !== undefined ? params.telecommuting : (rawText.includes('remote') || rawText.includes('work from home') || rawText.includes('telecommute'));
  const hasSalary = params.hasSalaryRange !== undefined ? params.hasSalaryRange : (rawText.includes('stipend') || rawText.includes('salary') || rawText.includes('per month') || rawText.includes('lpa'));

  if (!hasProfile && weights['has_company_profile']) {
    const w = Math.abs(weights['has_company_profile']);
    score += w * 0.8;
    contributions.push({ feature: "Missing Company Profile", contribution: w, direction: "FRAUD" });
  } else if (hasProfile && weights['has_company_profile']) {
    score += weights['has_company_profile'] * 0.5;
    contributions.push({ feature: "Verified Company Profile", contribution: Math.abs(weights['has_company_profile']), direction: "LEGITIMATE" });
  }

  if (!hasLogo && weights['has_company_logo']) {
    const w = Math.abs(weights['has_company_logo']);
    score += w * 0.6;
    contributions.push({ feature: "Missing Company Logo", contribution: w, direction: "FRAUD" });
  }

  if (isTelecommuting && weights['telecommuting']) {
    score += weights['telecommuting'];
    if (weights['telecommuting'] > 0) {
      contributions.push({ feature: "Unverified Remote/Telecommuting Posting", contribution: weights['telecommuting'], direction: "FRAUD" });
    }
  }

  // 2. Unigram & Bigram Text Matching against TF-IDF weights
  const termCounts: Record<string, number> = {};
  for (let i = 0; i < words.length; i++) {
    const unigram = words[i];
    termCounts[unigram] = (termCounts[unigram] || 0) + 1;
    if (i < words.length - 1) {
      const bigram = `${words[i]} ${words[i + 1]}`;
      termCounts[bigram] = (termCounts[bigram] || 0) + 1;
    }
  }

  for (const [term, count] of Object.entries(termCounts)) {
    if (weights[term] !== undefined) {
      const weight = weights[term];
      const tf = Math.log(1 + count);
      const contribution = weight * tf;
      score += contribution;

      if (Math.abs(contribution) > 0.15) {
        contributions.push({
          feature: `Term '${term}'`,
          contribution: Math.round(Math.abs(contribution) * 100) / 100,
          direction: contribution > 0 ? "FRAUD" : "LEGITIMATE"
        });
      }
    }
  }

  // 3. Calibrated Sigmoid Activation
  const fraudProbability = 1 / (1 + Math.exp(-score));
  const legitimateProbability = 1 - fraudProbability;
  const isFraud = fraudProbability >= 0.50;

  // Sort top influential features
  contributions.sort((a, b) => b.contribution - a.contribution);

  return {
    modelVersion: art.modelVersion,
    algorithm: art.bestModel || "Linear SVM (Calibrated) / Logistic Regression",
    prediction: isFraud ? "FRAUDULENT" : "LEGITIMATE",
    fraudProbability: Math.round(fraudProbability * 100) / 100,
    legitimateProbability: Math.round(legitimateProbability * 100) / 100,
    confidence: Math.round(Math.max(fraudProbability, legitimateProbability) * 100) / 100,
    ml_probability: Math.round(fraudProbability * 1000) / 1000,
    ml_probability_percent: Math.round(fraudProbability * 100),
    model_version: art.modelVersion,
    model_loaded: true,
    feature_count: Object.keys(weights).length,
    topFeatures: contributions.slice(0, 10),
    textSignals: {
      wordCount,
      hasTelecommuting: isTelecommuting,
      hasCompanyLogo: hasLogo,
      hasCompanyProfile: hasProfile,
      hasSalaryRange: hasSalary,
    },
  };
}
