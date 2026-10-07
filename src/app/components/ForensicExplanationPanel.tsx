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
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-emerald-400" />
          <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-slate-200">
            Multi-Signal Forensic Synthesis & Evidence Ledger
          </h3>
        </div>

        <span
          className={`text-xs font-mono px-2.5 py-1 rounded border ${
            normalizedConf > 50
              ? 'bg-rose-950/40 border-rose-800 text-rose-300'
              : 'bg-slate-900 border-slate-800 text-slate-300'
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
            <div className="p-4 rounded-md bg-slate-950 border border-slate-800 space-y-2">
              <h4 className="text-xs font-mono font-bold text-blue-400 uppercase tracking-wider flex items-center gap-1.5">
                <AlertCircle className="w-3.5 h-3.5" /> Observed Evidence
              </h4>
              <ul className="space-y-1.5 text-xs text-slate-300">
                {explanationSummary.whatWeFound.map((item, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-blue-400 font-mono mt-0.5">•</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Why It Matters */}
          {explanationSummary.whyItMatters && explanationSummary.whyItMatters.length > 0 && (
            <div className="p-4 rounded-md bg-slate-950 border border-slate-800 space-y-2">
              <h4 className="text-xs font-mono font-bold text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                <HelpCircle className="w-3.5 h-3.5" /> Technical Implication
              </h4>
              <ul className="space-y-1.5 text-xs text-slate-300">
                {explanationSummary.whyItMatters.map((item, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-amber-400 font-mono mt-0.5">•</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* What Is Verified */}
          {explanationSummary.whatIsVerified && explanationSummary.whatIsVerified.length > 0 && (
            <div className="p-4 rounded-md bg-slate-950 border border-slate-800 space-y-2">
              <h4 className="text-xs font-mono font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5" /> Verified Authenticity Signals
              </h4>
              <ul className="space-y-1.5 text-xs text-slate-300">
                {explanationSummary.whatIsVerified.map((item, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* What Should Be Done */}
          {explanationSummary.whatShouldBeDone && explanationSummary.whatShouldBeDone.length > 0 && (
            <div className="p-4 rounded-md bg-slate-950 border border-rose-900/60 space-y-2">
              <h4 className="text-xs font-mono font-bold text-rose-400 uppercase tracking-wider flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5" /> Actionable Directives
              </h4>
              <ul className="space-y-1.5 text-xs text-slate-200">
                {explanationSummary.whatShouldBeDone.map((item, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <ArrowRight className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
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
          <h4 className="text-xs font-mono uppercase font-bold text-slate-400 tracking-wider">
            Pattern Engine Matches
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {fraudPatterns.map((fp, i) => (
              <div
                key={i}
                className="p-3 rounded-md bg-rose-950/30 border border-rose-800/60 space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 rounded bg-rose-900/50 text-rose-300 font-mono text-[10px] font-bold">
                    {fp.patternId}
                  </span>
                  <span className="text-[10px] font-mono text-rose-400">
                    Confidence: {normalizeConfidence(fp.confidence)}%
                  </span>
                </div>
                <h5 className="text-xs font-bold text-slate-200">{fp.name}</h5>
                <p className="text-xs text-slate-400 leading-relaxed">{fp.description}</p>
              </div>
            ))}

            {legitimatePatterns.map((lp, i) => (
              <div
                key={i}
                className="p-3 rounded-md bg-emerald-950/30 border border-emerald-800/60 space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 rounded bg-emerald-900/50 text-emerald-300 font-mono text-[10px] font-bold">
                    {lp.patternId}
                  </span>
                  <span className="text-[10px] font-mono text-emerald-400">
                    Confidence: {normalizeConfidence(lp.confidence)}%
                  </span>
                </div>
                <h5 className="text-xs font-bold text-slate-200">{lp.name}</h5>
                <p className="text-xs text-slate-400 leading-relaxed">{lp.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
