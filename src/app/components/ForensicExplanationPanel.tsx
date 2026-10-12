// ==============================================================================
// LEGITIFY FORENSIC SUITE - FORENSIC EXPLANATION PANEL
// Authoritative, Enterprise-Grade Evidence Explanation Architecture
// ==============================================================================

import React from 'react';
import {
  AlertCircle,
  CheckCircle2,
  ShieldAlert,
  HelpCircle,
  ArrowRight,
  ShieldCheck,
  Binary,
  Layers,
} from 'lucide-react';
import {
  FraudPatternMatch,
  LegitimatePatternMatch,
  CounterEvidenceMatch,
} from '../../types/forensicTypes';

interface ForensicExplanationPanelProps {
  explanationSummary?: {
    whatWeFound: string[];
    whyItMatters: string[];
    whatIsVerified: string[];
    whatIsSuspicious: string[];
    whatShouldBeDone: string[];
  };
  fraudPatterns?: FraudPatternMatch[];
  legitimatePatterns?: LegitimatePatternMatch[];
  counterEvidence?: CounterEvidenceMatch[];
  fraudConfidence?: number;
}

const normalizeConfidence = (val: number | undefined): number => {
  if (val === undefined || val === null || isNaN(val)) return 85;
  if (val > 100) return Math.min(100, Math.round(val / 100));
  if (val <= 1 && val > 0) return Math.round(val * 100);
  return Math.min(100, Math.max(0, Math.round(val)));
};

export const ForensicExplanationPanel: React.FC<ForensicExplanationPanelProps> = ({
  explanationSummary,
  fraudPatterns = [],
  legitimatePatterns = [],
  counterEvidence = [],
  fraudConfidence = 10,
}) => {
  if (
    !explanationSummary &&
    fraudPatterns.length === 0 &&
    legitimatePatterns.length === 0
  ) {
    return null;
  }

  const normalizedConf = normalizeConfidence(fraudConfidence);

  return (
    <div className="space-y-5 font-sans">
      {/* Header Bar */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-200">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-blue-600" />
          <h3 className="text-sm font-semibold tracking-tight text-slate-900">
            Multi-Signal Forensic Synthesis & Evidence Ledger
          </h3>
        </div>

        <span
          className={`text-xs font-medium px-2.5 py-1 rounded-md border ${
            normalizedConf > 50
              ? 'bg-rose-50 border-rose-200 text-rose-700'
              : 'bg-slate-50 border-slate-200 text-slate-700'
          }`}
        >
          Manipulation Risk Index: {normalizedConf}%
        </span>
      </div>

      {/* Structured 4-Block Forensic Reasoning */}
      {explanationSummary && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* What We Found */}
          {explanationSummary.whatWeFound && explanationSummary.whatWeFound.length > 0 && (
            <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-2">
              <h4 className="text-xs font-semibold text-blue-700 uppercase tracking-wider flex items-center gap-1.5">
                <AlertCircle className="w-3.5 h-3.5 text-blue-600" /> Observed Evidence
              </h4>
              <ul className="space-y-1.5 text-xs text-slate-700">
                {explanationSummary.whatWeFound.map((item, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-blue-600 font-bold mt-0.5">•</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Why It Matters */}
          {explanationSummary.whyItMatters && explanationSummary.whyItMatters.length > 0 && (
            <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-2">
              <h4 className="text-xs font-semibold text-amber-700 uppercase tracking-wider flex items-center gap-1.5">
                <HelpCircle className="w-3.5 h-3.5 text-amber-600" /> Technical Implication
              </h4>
              <ul className="space-y-1.5 text-xs text-slate-700">
                {explanationSummary.whyItMatters.map((item, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-amber-600 font-bold mt-0.5">•</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* What Is Verified */}
          {explanationSummary.whatIsVerified && explanationSummary.whatIsVerified.length > 0 && (
            <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-2">
              <h4 className="text-xs font-semibold text-emerald-700 uppercase tracking-wider flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> Verified Authenticity Signals
              </h4>
              <ul className="space-y-1.5 text-xs text-slate-700">
                {explanationSummary.whatIsVerified.map((item, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0 mt-0.5" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* What Should Be Done */}
          {explanationSummary.whatShouldBeDone && explanationSummary.whatShouldBeDone.length > 0 && (
            <div className="p-4 rounded-xl bg-white border border-rose-200 shadow-xs space-y-2">
              <h4 className="text-xs font-semibold text-rose-700 uppercase tracking-wider flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-rose-600" /> Actionable Directives
              </h4>
              <ul className="space-y-1.5 text-xs text-slate-700">
                {explanationSummary.whatShouldBeDone.map((item, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <ArrowRight className="w-3.5 h-3.5 text-rose-600 shrink-0 mt-0.5" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Pattern Library Evaluator Matches */}
      {(fraudPatterns.length > 0 || legitimatePatterns.length > 0) && (
        <div className="space-y-3 pt-2">
          <h4 className="text-xs uppercase font-semibold text-slate-500 tracking-wider">
            Pattern Engine Matches
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {fraudPatterns.map((fp, i) => (
              <div
                key={i}
                className="p-3.5 rounded-lg bg-rose-50/70 border border-rose-200 space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 rounded bg-rose-100 text-rose-800 font-mono text-[10px] font-bold">
                    {fp.patternId}
                  </span>
                  <span className="text-[10px] font-medium text-rose-700">
                    Confidence: {normalizeConfidence(fp.confidence)}%
                  </span>
                </div>
                <h5 className="text-xs font-semibold text-rose-950">{fp.name}</h5>
                <p className="text-xs text-rose-800 leading-relaxed">{fp.description}</p>
              </div>
            ))}

            {legitimatePatterns.map((lp, i) => (
              <div
                key={i}
                className="p-3.5 rounded-lg bg-emerald-50/70 border border-emerald-200 space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 font-mono text-[10px] font-bold">
                    {lp.patternId}
                  </span>
                  <span className="text-[10px] font-medium text-emerald-700">
                    Confidence: {normalizeConfidence(lp.confidence)}%
                  </span>
                </div>
                <h5 className="text-xs font-semibold text-emerald-950">{lp.name}</h5>
                <p className="text-xs text-emerald-800 leading-relaxed">{lp.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
