// ==============================================================================
// LEGITIFY FORENSIC SUITE - ENTERPRISE FORENSIC REPORT DASHBOARD
// Authoritative Cybersecurity Data-Dense UI with Recharts Visualizations
// ==============================================================================

import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  FileText,
  Copy,
  Check,
  Binary,
  Layers,
  Search,
  Cpu,
  BarChart3,
  Calendar,
  Eye,
  ArrowRight,
  Download,
  RotateCcw,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
  CartesianGrid,
  AreaChart,
  Area,
} from 'recharts';
import { CompleteForensicReport } from '../../../lib/forensics/types';

interface ForensicReportDashboardProps {
  report: CompleteForensicReport;
  onNewScan: () => void;
  onExportPdf?: () => void;
}

export const ForensicReportDashboard: React.FC<ForensicReportDashboardProps> = ({
  report,
  onNewScan,
  onExportPdf,
}) => {
  const [activeTab, setActiveTab] = useState<'reasoning' | 'metadata' | 'pixel' | 'ocr'>('reasoning');
  const [copiedHash, setCopiedHash] = useState(false);
  const [metadataSearch, setMetadataSearch] = useState('');
  const [ocrSearch, setOcrSearch] = useState('');

  const { custody, validation, metadata, pixel, ocr, scoring, sanitizedPreviewUrl } = report;

  const copyHash = () => {
    navigator.clipboard.writeText(custody.sha256Hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  // 1. Forensic Weight Breakdown for Recharts
  const weightBreakdownData = [
    {
      name: 'Metadata Integrity',
      score: metadata.metadataScore,
      weight: '30%',
      weightedContribution: Math.round(metadata.metadataScore * 0.3),
      fill: metadata.modifyingSoftwareFlagged ? '#F43F5E' : '#10B981',
    },
    {
      name: 'Pixel Variance / Splicing',
      score: pixel.pixelScore,
      weight: '40%',
      weightedContribution: Math.round(pixel.pixelScore * 0.4),
      fill: pixel.blockVarianceDisparity > 0.45 ? '#F59E0B' : '#0D9488',
    },
    {
      name: 'OCR Optical Confidence',
      score: ocr.ocrScore,
      weight: '30%',
      weightedContribution: Math.round(ocr.ocrScore * 0.3),
      fill: ocr.suspiciousKeywordsFound.length > 0 ? '#F43F5E' : '#3B82F6',
    },
  ];

  // 2. Filtered Metadata Tags
  const filteredTags = metadata.tags.filter(
    (t) =>
      t.tag.toLowerCase().includes(metadataSearch.toLowerCase()) ||
      t.sanitizedValue.toLowerCase().includes(metadataSearch.toLowerCase()) ||
      t.group.toLowerCase().includes(metadataSearch.toLowerCase())
  );

  // 3. Filtered OCR Words
  const filteredWords = ocr.words.filter((w) =>
    w.sanitizedText.toLowerCase().includes(ocrSearch.toLowerCase())
  );

  const getVerdictBadge = () => {
    switch (scoring.verdictSeverity) {
      case 'low':
        return {
          bg: 'bg-emerald-950/40 border-emerald-800 text-emerald-300',
          indicator: 'bg-emerald-400',
          icon: <ShieldCheck className="w-5 h-5 text-emerald-400" />,
        };
      case 'moderate':
        return {
          bg: 'bg-amber-950/40 border-amber-800 text-amber-300',
          indicator: 'bg-amber-400',
          icon: <AlertTriangle className="w-5 h-5 text-amber-400" />,
        };
      case 'critical':
      default:
        return {
          bg: 'bg-rose-950/40 border-rose-800 text-rose-300',
          indicator: 'bg-rose-400',
          icon: <ShieldAlert className="w-5 h-5 text-rose-400" />,
        };
    }
  };

  const badge = getVerdictBadge();

  return (
    <div className="w-full space-y-6 font-sans text-slate-100">
      {/* Top Action Bar */}
      <div className="flex items-center justify-between flex-wrap gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono tracking-widest uppercase px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400">
              FORENSIC VERIFICATION AUDIT
            </span>
            <span className="text-[11px] font-mono text-slate-500">
              Duration: {report.analysisDurationMs}ms
            </span>
          </div>
          <h2 className="text-xl font-bold text-slate-100 mt-1 tracking-tight">
            {custody.fileName}
          </h2>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={onNewScan}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-900 border border-slate-800 text-xs font-semibold text-slate-300 hover:bg-slate-800 transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            New Inspection
          </button>
          {onExportPdf && (
            <button
              onClick={onExportPdf}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-md bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-slate-950 transition-colors shadow-sm"
            >
              <Download className="w-3.5 h-3.5" />
              Export Report
            </button>
          )}
        </div>
      </div>

      {/* Cryptographic Chain of Custody Ledger */}
      <div className="p-4 rounded-md bg-slate-950 border border-slate-800 space-y-3">
        <div className="flex items-center justify-between flex-wrap gap-2 text-xs">
          <div className="flex items-center gap-2 font-mono text-slate-400">
            <Binary className="w-4 h-4 text-emerald-400" />
            <span className="font-semibold text-slate-300">CRYPTOGRAPHIC CHAIN OF CUSTODY</span>
            <span className="text-slate-600">|</span>
            <span>{custody.custodyId}</span>
          </div>
          <span className="font-mono text-slate-500 text-[11px]">
            Ingestion: {new Date(custody.ingestionTimestamp).toUTCString()}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 pt-1">
          <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800/80">
            <span className="text-[10px] font-mono uppercase text-slate-500 block">SHA-256 Digest</span>
            <div className="flex items-center justify-between gap-1 mt-0.5">
              <span className="text-xs font-mono text-slate-300 truncate" title={custody.sha256Hash}>
                {custody.sha256Hash}
              </span>
              <button
                type="button"
                onClick={copyHash}
                className="text-slate-400 hover:text-slate-200 transition-colors shrink-0"
              >
                {copiedHash ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              </button>
            </div>
          </div>

          <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800/80">
            <span className="text-[10px] font-mono uppercase text-slate-500 block">Magic Bytes Header</span>
            <span className="text-xs font-mono text-slate-200 block mt-0.5">
              {custody.magicSignatureHex} ({validation.detectedFormat})
            </span>
          </div>

          <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800/80">
            <span className="text-[10px] font-mono uppercase text-slate-500 block">File Allocation</span>
            <span className="text-xs font-mono text-slate-200 block mt-0.5">
              {custody.fileSizeFormatted} ({custody.fileSizeBytes.toLocaleString()} bytes)
            </span>
          </div>

          <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800/80">
            <span className="text-[10px] font-mono uppercase text-slate-500 block">MIME Protocol</span>
            <span className="text-xs font-mono text-slate-200 block mt-0.5">
              {custody.detectedMimeType}
            </span>
          </div>
        </div>
      </div>

      {/* Main Score & Verdict Summary */}
      <div className={`p-6 rounded-md border ${badge.bg} flex flex-col md:flex-row items-start md:items-center justify-between gap-6`}>
        <div className="space-y-2 max-w-2xl">
          <div className="flex items-center gap-2.5">
            {badge.icon}
            <span className="text-sm font-mono font-bold tracking-wide uppercase">
              {scoring.verdictLabel}
            </span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-900/80 border border-slate-800 text-slate-300">
              Confidence: {scoring.confidenceMetric}%
            </span>
          </div>
          <p className="text-xs text-slate-200 leading-relaxed font-sans">
            {scoring.executiveSummary}
          </p>
        </div>

        <div className="flex items-center gap-6 shrink-0 border-t md:border-t-0 md:border-l border-slate-800/80 pt-4 md:pt-0 md:pl-6">
          <div className="text-center">
            <span className="text-[11px] font-mono uppercase text-slate-400 block mb-0.5">Authenticity</span>
            <span className="text-3xl font-mono font-bold text-slate-100">
              {scoring.authenticityScore}
              <span className="text-sm text-slate-500">/100</span>
            </span>
          </div>

          <div className="text-center">
            <span className="text-[11px] font-mono uppercase text-slate-400 block mb-0.5">Manipulation Risk</span>
            <span
              className={`text-3xl font-mono font-bold ${
                scoring.manipulationProbability > 40 ? 'text-rose-400' : 'text-emerald-400'
              }`}
            >
              {scoring.manipulationProbability}%
            </span>
          </div>
        </div>
      </div>

      {/* Visual Analytics Grid (Recharts) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Chart 1: Weighted Dimension Breakdown */}
        <div className="p-4 rounded-md bg-slate-950 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <BarChart3 className="w-3.5 h-3.5 text-emerald-400" />
              Dynamic Scoring Breakdown
            </h4>
            <span className="text-[10px] font-mono text-slate-500">100% Total Weight</span>
          </div>
          <p className="text-[11px] text-slate-400">
            Weighted contribution: Metadata (30%) + Pixel Variance (40%) + OCR Confidence (30%).
          </p>
          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={weightBreakdownData} layout="vertical" margin={{ top: 5, right: 15, left: 10, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" horizontal={false} />
                <XAxis type="number" domain={[0, 100]} stroke="#64748B" tick={{ fontSize: 10, fill: '#94A3B8' }} />
                <YAxis dataKey="name" type="category" width={110} stroke="#64748B" tick={{ fontSize: 10, fill: '#CBD5E1' }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0F172A', borderColor: '#334155', borderRadius: 4, fontSize: 11 }}
                  formatter={(val: any, name: any, item: any) => [`${val}/100 (${item.payload.weight} weight)`, 'Sub-Score']}
                />
                <Bar dataKey="score" radius={[0, 3, 3, 0]}>
                  {weightBreakdownData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Chart 2: Pixel Luminance Distribution (Canvas API) */}
        <div className="p-4 rounded-md bg-slate-950 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Layers className="w-3.5 h-3.5 text-teal-400" />
              Pixel Luminance Histogram
            </h4>
            <span className="text-[10px] font-mono text-slate-500">16-Bin Distribution</span>
          </div>
          <p className="text-[11px] text-slate-400">
            Luminance distribution across {pixel.totalPixels.toLocaleString()} analyzed canvas pixels.
          </p>
          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={pixel.histogram} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" />
                <XAxis dataKey="binRange" stroke="#64748B" tick={{ fontSize: 9, fill: '#94A3B8' }} interval={3} />
                <YAxis stroke="#64748B" tick={{ fontSize: 9, fill: '#94A3B8' }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0F172A', borderColor: '#334155', borderRadius: 4, fontSize: 11 }}
                  formatter={(val: any) => [`${Number(val).toLocaleString()} px`, 'Pixel Count']}
                />
                <Area type="monotone" dataKey="count" stroke="#0D9488" fill="#0D9488" fillOpacity={0.25} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Chart 3: OCR Word Confidence Dispersion */}
        <div className="p-4 rounded-md bg-slate-950 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <FileText className="w-3.5 h-3.5 text-blue-400" />
              OCR Confidence Dispersion
            </h4>
            <span className="text-[10px] font-mono text-slate-500">
              Avg: {ocr.averageConfidence}%
            </span>
          </div>
          <p className="text-[11px] text-slate-400">
            Word count breakdown grouped by Tesseract optical transcription confidence.
          </p>
          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={ocr.confidenceBuckets} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" />
                <XAxis dataKey="range" stroke="#64748B" tick={{ fontSize: 10, fill: '#94A3B8' }} />
                <YAxis stroke="#64748B" tick={{ fontSize: 9, fill: '#94A3B8' }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0F172A', borderColor: '#334155', borderRadius: 4, fontSize: 11 }}
                  formatter={(val: any) => [`${val} words`, 'Count']}
                />
                <Bar dataKey="count" fill="#3B82F6" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Forensic Navigation Tabs */}
      <div className="border-b border-slate-800 flex items-center gap-1">
        <button
          onClick={() => setActiveTab('reasoning')}
          className={`px-4 py-2.5 text-xs font-mono font-semibold transition-colors border-b-2 -mb-px ${
            activeTab === 'reasoning'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Structured Findings
        </button>

        <button
          onClick={() => setActiveTab('metadata')}
          className={`px-4 py-2.5 text-xs font-mono font-semibold transition-colors border-b-2 -mb-px flex items-center gap-1.5 ${
            activeTab === 'metadata'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          EXIF & Header Ledger
          <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
            {metadata.tags.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('pixel')}
          className={`px-4 py-2.5 text-xs font-mono font-semibold transition-colors border-b-2 -mb-px ${
            activeTab === 'pixel'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Pixel Forensics Matrix
        </button>

        <button
          onClick={() => setActiveTab('ocr')}
          className={`px-4 py-2.5 text-xs font-mono font-semibold transition-colors border-b-2 -mb-px flex items-center gap-1.5 ${
            activeTab === 'ocr'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          OCR Optical Ledger
          <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
            {ocr.wordCount}
          </span>
        </button>
      </div>

      {/* Tab 1: Structured Reasoning */}
      {activeTab === 'reasoning' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* What We Found */}
          <div className="p-4 rounded-md bg-slate-950 border border-slate-800 space-y-2">
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Search className="w-3.5 h-3.5 text-blue-400" />
              Observed Forensic Facts
            </h4>
            <ul className="space-y-1.5 text-xs text-slate-300 font-sans">
              {scoring.reasons.whatWeFound.map((item, i) => (
                <li key={i} className="flex items-start gap-2">
                  <span className="text-blue-400 font-mono">•</span>
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Why It Matters */}
          <div className="p-4 rounded-md bg-slate-950 border border-slate-800 space-y-2">
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Cpu className="w-3.5 h-3.5 text-amber-400" />
              Security Implications
            </h4>
            <ul className="space-y-1.5 text-xs text-slate-300 font-sans">
              {scoring.reasons.whyItMatters.length > 0 ? (
                scoring.reasons.whyItMatters.map((item, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-amber-400 font-mono">•</span>
                    <span>{item}</span>
                  </li>
                ))
              ) : (
                <li className="text-slate-500 italic">No adverse security anomalies recorded.</li>
              )}
            </ul>
          </div>

          {/* Verified Authenticity Signals */}
          <div className="p-4 rounded-md bg-slate-950 border border-slate-800 space-y-2">
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-2">
              <ShieldCheck className="w-3.5 h-3.5" />
              Verified Authenticity Signals
            </h4>
            <ul className="space-y-1.5 text-xs text-slate-300 font-sans">
              {scoring.reasons.verifiedSignals.map((item, i) => (
                <li key={i} className="flex items-start gap-2">
                  <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Risk Indicators & Guidance */}
          <div className="p-4 rounded-md bg-slate-950 border border-slate-800 space-y-2">
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-rose-400 flex items-center gap-2">
              <ShieldAlert className="w-3.5 h-3.5" />
              Actionable Guidance & Directives
            </h4>
            <ul className="space-y-1.5 text-xs text-slate-300 font-sans">
              {scoring.reasons.recommendedActions.map((item, i) => (
                <li key={i} className="flex items-start gap-2">
                  <ArrowRight className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* Tab 2: EXIF & Header Ledger */}
      {activeTab === 'metadata' && (
        <div className="p-4 rounded-md bg-slate-950 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div className="space-y-0.5">
              <h4 className="text-xs font-mono font-bold uppercase text-slate-200">
                EXIF / XMP / TIFF Metadata Inspection
              </h4>
              <p className="text-[11px] text-slate-400">
                Extracted metadata tags sanitized against script injection via DOMPurify.
              </p>
            </div>

            <div className="relative w-64">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
              <input
                type="text"
                placeholder="Filter metadata tags..."
                value={metadataSearch}
                onChange={(e) => setMetadataSearch(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 rounded bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-slate-700"
              />
            </div>
          </div>

          {filteredTags.length > 0 ? (
            <div className="overflow-x-auto border border-slate-800 rounded">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-900/80 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                    <th className="p-2.5">Tag Name</th>
                    <th className="p-2.5">Group</th>
                    <th className="p-2.5">Extracted Value</th>
                    <th className="p-2.5">Forensic Implication</th>
                    <th className="p-2.5">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80 font-mono text-[11px]">
                  {filteredTags.map((entry, i) => (
                    <tr key={i} className="hover:bg-slate-900/40">
                      <td className="p-2.5 text-slate-300 font-semibold">{entry.tag}</td>
                      <td className="p-2.5 text-slate-500">{entry.group}</td>
                      <td className="p-2.5 text-slate-200 max-w-xs truncate" title={entry.sanitizedValue}>
                        {entry.sanitizedValue}
                      </td>
                      <td className="p-2.5 text-slate-400 max-w-sm truncate" title={entry.implication}>
                        {entry.implication}
                      </td>
                      <td className="p-2.5">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            entry.status === 'ALTERED'
                              ? 'bg-rose-950 border border-rose-800 text-rose-300'
                              : entry.status === 'VERIFIED'
                              ? 'bg-emerald-950 border border-emerald-800 text-emerald-300'
                              : 'bg-slate-900 text-slate-400'
                          }`}
                        >
                          {entry.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-8 text-center border border-dashed border-slate-800 rounded text-slate-500 text-xs font-mono">
              {metadata.hasExifData
                ? 'No tags matching current filter.'
                : 'No EXIF or XMP headers present in this file (headers stripped or vector format).'}
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Pixel Forensics Matrix */}
      {activeTab === 'pixel' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {/* Visual Canvas Display */}
          <div className="p-4 rounded-md bg-slate-950 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-mono font-bold uppercase text-slate-200 flex items-center gap-2">
                <Eye className="w-3.5 h-3.5 text-teal-400" />
                Sanitized Visual Display
              </h4>
              <span className="text-[10px] font-mono text-emerald-400">EXIF Chunks Stripped</span>
            </div>

            {sanitizedPreviewUrl ? (
              <div className="rounded border border-slate-800 bg-slate-900 overflow-hidden flex items-center justify-center max-h-96">
                <img
                  src={sanitizedPreviewUrl}
                  alt="Sanitized preview"
                  className="max-h-96 w-auto object-contain"
                />
              </div>
            ) : (
              <div className="h-64 rounded border border-dashed border-slate-800 bg-slate-900/40 flex items-center justify-center text-slate-500 text-xs font-mono">
                Visual preview not available for raw PDF document
              </div>
            )}
            <p className="text-[11px] text-slate-500 font-mono">
              Rendered through an isolated canvas buffer to prevent client-side script execution.
            </p>
          </div>

          {/* Mathematical Matrix */}
          <div className="p-4 rounded-md bg-slate-950 border border-slate-800 space-y-4">
            <h4 className="text-xs font-mono font-bold uppercase text-slate-200">
              Deterministic Pixel Metrics
            </h4>

            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 rounded bg-slate-900/60 border border-slate-800">
                <span className="text-[10px] font-mono uppercase text-slate-500 block">Sampled Dimensions</span>
                <span className="text-sm font-mono font-bold text-slate-200 block mt-0.5">
                  {pixel.width} × {pixel.height} px
                </span>
                <span className="text-[10px] text-slate-500">
                  {pixel.totalPixels.toLocaleString()} total cells
                </span>
              </div>

              <div className="p-3 rounded bg-slate-900/60 border border-slate-800">
                <span className="text-[10px] font-mono uppercase text-slate-500 block">Mean Luminance</span>
                <span className="text-sm font-mono font-bold text-slate-200 block mt-0.5">
                  {pixel.meanLuminance} <span className="text-xs text-slate-500">(±{pixel.stdDevLuminance})</span>
                </span>
                <span className="text-[10px] text-slate-500">ITU-R BT.601 spectrum</span>
              </div>

              <div className="p-3 rounded bg-slate-900/60 border border-slate-800">
                <span className="text-[10px] font-mono uppercase text-slate-500 block">8×8 Block Disparity</span>
                <span
                  className={`text-sm font-mono font-bold block mt-0.5 ${
                    pixel.blockVarianceDisparity > 0.45 ? 'text-amber-400' : 'text-emerald-400'
                  }`}
                >
                  {(pixel.blockVarianceDisparity * 100).toFixed(1)}%
                </span>
                <span className="text-[10px] text-slate-500">DCT noise consistency</span>
              </div>

              <div className="p-3 rounded bg-slate-900/60 border border-slate-800">
                <span className="text-[10px] font-mono uppercase text-slate-500 block">Laplacian Edge Variance</span>
                <span className="text-sm font-mono font-bold text-slate-200 block mt-0.5">
                  {pixel.laplacianEdgeVariance}
                </span>
                <span className="text-[10px] text-slate-500">High-frequency sharpness</span>
              </div>

              <div className="p-3 rounded bg-slate-900/60 border border-slate-800">
                <span className="text-[10px] font-mono uppercase text-slate-500 block">Clipping Saturation</span>
                <span className="text-sm font-mono font-bold text-slate-200 block mt-0.5">
                  {(pixel.clippingRatio * 100).toFixed(1)}%
                </span>
                <span className="text-[10px] text-slate-500">Pure white/black ratio</span>
              </div>

              <div className="p-3 rounded bg-slate-900/60 border border-slate-800">
                <span className="text-[10px] font-mono uppercase text-slate-500 block">Compression Uniformity</span>
                <span className="text-sm font-mono font-bold text-slate-200 block mt-0.5">
                  {pixel.compressionArtifactIndex}/100
                </span>
                <span className="text-[10px] text-slate-500">Calculated artifact index</span>
              </div>
            </div>

            <div className="p-3 rounded bg-slate-900 border border-slate-800/80 space-y-1.5">
              <span className="text-[11px] font-mono font-bold uppercase text-slate-300 block">
                Forensic Interpretations
              </span>
              <ul className="space-y-1 text-xs text-slate-400 font-mono">
                {pixel.pixelFindings.map((f, i) => (
                  <li key={i}>• {f}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Tab 4: OCR Optical Ledger */}
      {activeTab === 'ocr' && (
        <div className="p-4 rounded-md bg-slate-950 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div className="space-y-0.5">
              <h4 className="text-xs font-mono font-bold uppercase text-slate-200">
                Tesseract OCR Transcription & Confidence Spectrum
              </h4>
              <p className="text-[11px] text-slate-400">
                {ocr.wordCount} words transcribed with per-token confidence. All output sanitized with DOMPurify.
              </p>
            </div>

            <div className="relative w-64">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
              <input
                type="text"
                placeholder="Search extracted tokens..."
                value={ocrSearch}
                onChange={(e) => setOcrSearch(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 rounded bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-slate-700"
              />
            </div>
          </div>

          {ocr.suspiciousKeywordsFound.length > 0 && (
            <div className="p-3 rounded bg-rose-950/40 border border-rose-800 text-rose-300 text-xs font-mono space-y-1">
              <div className="font-bold flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                UNAUTHORIZED FINANCIAL / CONTACT DEMANDS DETECTED IN TEXT:
              </div>
              <div>Keywords: [{ocr.suspiciousKeywordsFound.join(', ')}]</div>
            </div>
          )}

          {/* Word Confidence Tokens */}
          <div className="p-4 rounded bg-slate-900/50 border border-slate-800 max-h-72 overflow-y-auto space-y-2">
            <span className="text-[10px] font-mono uppercase text-slate-500 block">
              Confidence Tokens (Word Level)
            </span>
            <div className="flex flex-wrap gap-1.5">
              {filteredWords.map((word, i) => (
                <span
                  key={i}
                  title={`Confidence: ${word.confidence}%`}
                  className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono border ${
                    word.isSuspiciousKeyword
                      ? 'bg-rose-950 border-rose-700 text-rose-300 font-bold'
                      : word.confidence >= 80
                      ? 'bg-slate-900 border-slate-800 text-slate-200'
                      : word.confidence >= 60
                      ? 'bg-amber-950/40 border-amber-800 text-amber-300'
                      : 'bg-rose-950/40 border-rose-900 text-rose-400'
                  }`}
                >
                  <span>{word.sanitizedText}</span>
                  <span className="text-[9px] opacity-70">{word.confidence}%</span>
                </span>
              ))}
            </div>
          </div>

          {/* Sanitized Plain Text Block */}
          <div className="p-4 rounded bg-slate-900/80 border border-slate-800 space-y-2">
            <span className="text-[10px] font-mono uppercase text-slate-500 block">
              Full Sanitized Transcription
            </span>
            <pre className="text-xs font-mono text-slate-300 whitespace-pre-wrap leading-relaxed max-h-60 overflow-y-auto select-all">
              {ocr.sanitizedText || '(Zero text extracted from document)'}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
