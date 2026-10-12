import React, { useState } from 'react';
import { Shield, AlertTriangle, ExternalLink, RefreshCw, CheckCircle, Search, Filter, Layers, Globe, ShieldCheck } from 'lucide-react';
import { PublicExperienceResult, PublicExperience, ComplaintCluster, ProviderStatusRecord } from '../../types/forensicTypes';

interface PublicExperiencePanelProps {
  data?: PublicExperienceResult;
  companyName: string;
  scanId?: string;
  onReinvestigate?: () => Promise<void>;
}

export const PublicExperiencePanel: React.FC<PublicExperiencePanelProps> = ({
  data,
  companyName,
  scanId,
  onReinvestigate,
}) => {
  const [activeFilter, setActiveFilter] = useState<string>('ALL');
  const [selectedCluster, setSelectedCluster] = useState<string | null>(null);
  const [isReinvestigating, setIsReinvestigating] = useState<boolean>(false);
  const [reinvestigateError, setReinvestigateError] = useState<string | null>(null);

  const sources: PublicExperience[] = data?.sources || [];
  const clusters: ComplaintCluster[] = data?.clusters || [];
  const providers: ProviderStatusRecord[] = (data as any)?.providers || (data as any)?.providerStatuses || [];

  const handleReinvestigateClick = async () => {
    if (!onReinvestigate || isReinvestigating) return;
    setIsReinvestigating(true);
    setReinvestigateError(null);
    try {
      await onReinvestigate();
    } catch (err: any) {
      setReinvestigateError(err?.message || 'Failed to re-run investigation');
    } finally {
      setIsReinvestigating(false);
    }
  };

  // Filter sources based on tab
  const filteredSources = sources.filter(s => {
    if (activeFilter === 'ALL') return true;
    if (activeFilter === 'FRAUD') {
      return s.experienceType.includes('SCAM') || s.experienceType.includes('FRAUD') || s.experienceType.includes('IMPERSONATION');
    }
    if (activeFilter === 'PAYMENT') {
      return s.experienceType.includes('PAYMENT');
    }
    if (activeFilter === 'RECRUITER') {
      return s.matchedEntities?.some(m => m.includes('EMAIL') || m.includes('DOMAIN')) || (s as any).matchedEntity === 'RECRUITER_EMAIL' || (s as any).matchedEntity === 'DOMAIN' || s.experienceType.includes('IMPERSONATION');
    }
    if (activeFilter === 'WARNINGS') {
      return s.experienceType.includes('WARNING') || s.experienceType.includes('OFFICIAL');
    }
    if (activeFilter === 'POSITIVE') {
      return s.experienceType.includes('POSITIVE') || s.experienceType.includes('VERIFIED');
    }
    return true;
  });

  const fraudCount = sources.filter(s => s.experienceType.includes('SCAM') || s.experienceType.includes('FRAUD')).length;
  const paymentCount = sources.filter(s => s.experienceType.includes('PAYMENT')).length;
  const warningCount = sources.filter(s => s.experienceType.includes('WARNING') || s.experienceType.includes('OFFICIAL')).length;
  const positiveCount = sources.filter(s => s.experienceType.includes('POSITIVE')).length;
  const isLive = Boolean(data?.isLive || (data?.status as any) === 'LIVE' || data?.status === 'COMPLETED');
  const searchTimestamp = data?.searchedAt || (data as any)?.retrievedAt;

  return (
    <div className="space-y-6 font-sans">
      {/* Header with Title, Status Badges, and Re-Investigate Action */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-xl bg-white border border-slate-200 shadow-xs">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <Globe className="w-5 h-5 text-blue-600" />
            <h3 className="text-lg font-bold text-slate-900">
              Real-Time Public Experience & Complaint Intelligence
            </h3>
          </div>
          <p className="text-xs text-slate-500 font-sans">
            Query-driven investigation of candidate reports across community forums & corporate caution notices
          </p>
          <div className="flex flex-wrap items-center gap-2 pt-2">
            <span className={`px-2.5 py-1 rounded-md text-[11px] font-sans font-semibold uppercase tracking-wider ${
              isLive
                ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                : 'bg-amber-50 text-amber-700 border border-amber-200'
            }`}>
              {isLive ? 'LIVE AUDIT' : 'ARCHIVED EVIDENCE'}
            </span>
            <span className="text-xs font-sans text-slate-500">
              Retrieved: {searchTimestamp ? new Date(searchTimestamp).toLocaleTimeString() : new Date().toLocaleTimeString()}
            </span>
            {data?.investigationId && (
              <span className="text-[11px] font-mono text-slate-500">
                · ID: <strong className="text-slate-800">{data.investigationId}</strong>
              </span>
            )}
          </div>
        </div>

        {onReinvestigate && (
          <button
            onClick={handleReinvestigateClick}
            disabled={isReinvestigating}
            className={`px-4 py-2 rounded-lg font-medium text-xs font-sans transition-colors flex items-center gap-2 cursor-pointer shadow-xs ${
              isReinvestigating
                ? 'bg-slate-100 text-slate-400 cursor-not-allowed border border-slate-200'
                : 'bg-slate-50 hover:bg-slate-100 text-slate-700 border border-slate-200'
            }`}
          >
            <RefreshCw className={`w-3.5 h-3.5 text-blue-600 ${isReinvestigating ? 'animate-spin' : ''}`} />
            <span>{isReinvestigating ? 'Investigating Live...' : 'Investigate Again'}</span>
          </button>
        )}
      </div>

      {reinvestigateError && (
        <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-xs font-sans text-rose-700 flex items-center gap-3">
          <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
          <span>{reinvestigateError}</span>
        </div>
      )}

      {/* Summary Metrics Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs text-center">
          <span className="text-2xl font-bold text-slate-900">{sources.length}</span>
          <span className="text-[10px] font-sans font-medium uppercase text-slate-500 block mt-1 tracking-wider">Sources Evaluated</span>
        </div>
        <div className="p-4 rounded-xl bg-white border border-rose-200 shadow-xs text-center">
          <span className="text-2xl font-bold text-rose-600">{fraudCount}</span>
          <span className="text-[10px] font-sans font-medium uppercase text-rose-700 block mt-1 tracking-wider">Fraud Reports</span>
        </div>
        <div className="p-4 rounded-xl bg-white border border-amber-200 shadow-xs text-center">
          <span className="text-2xl font-bold text-amber-600">{paymentCount}</span>
          <span className="text-[10px] font-sans font-medium uppercase text-amber-700 block mt-1 tracking-wider">Payment Demands</span>
        </div>
        <div className="p-4 rounded-xl bg-white border border-amber-200 shadow-xs text-center">
          <span className="text-2xl font-bold text-amber-600">{warningCount}</span>
          <span className="text-[10px] font-sans font-medium uppercase text-amber-700 block mt-1 tracking-wider">Caution Notices</span>
        </div>
        <div className="p-4 rounded-xl bg-white border border-emerald-200 shadow-xs text-center col-span-2 sm:col-span-1">
          <span className="text-2xl font-bold text-emerald-600">{positiveCount}</span>
          <span className="text-[10px] font-sans font-medium uppercase text-emerald-700 block mt-1 tracking-wider">Positive Signals</span>
        </div>
      </div>

      {/* Real-Source Integrity & Provider Audit Bar */}
      {providers.length > 0 && (
        <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs flex flex-wrap items-center justify-between gap-3 text-xs font-sans">
          <div className="flex items-center gap-2 text-slate-700">
            <ShieldCheck className="w-4 h-4 text-emerald-600" />
            <span className="font-semibold text-slate-900">Source Integrity Audit:</span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {providers.map((p, i) => (
              <span
                key={i}
                className={`px-2.5 py-1 rounded-md text-[11px] font-sans font-medium flex items-center gap-1.5 ${
                  p.status === 'LIVE'
                    ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                    : p.status === 'NOT_FOUND'
                    ? 'bg-slate-50 text-slate-500 border border-slate-200'
                    : 'bg-amber-50 text-amber-700 border border-amber-200'
                }`}
              >
                <span>{p.status === 'LIVE' ? '●' : p.status === 'NOT_FOUND' ? '○' : '▲'}</span>
                <span>{p.provider}: {p.status} {(p as any).recordsReturned !== undefined || (p as any).resultCount !== undefined ? `(${(p as any).recordsReturned ?? (p as any).resultCount} found)` : ''}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Complaint Clusters (Corroborated Multi-Signal Correlation) */}
      {clusters.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-rose-600" />
            <h4 className="text-xs font-bold text-slate-700 uppercase font-sans tracking-wider">
              Corroborated Incident Clusters ({clusters.length})
            </h4>
          </div>
          <div className="grid grid-cols-1 gap-3">
            {clusters.map((cluster, i) => (
              <div
                key={i}
                className="p-5 rounded-xl bg-rose-50/70 border border-rose-200 space-y-3 shadow-xs"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <span className="px-2 py-0.5 rounded bg-rose-100 text-rose-800 font-mono font-bold text-xs">
                      {cluster.clusterId}
                    </span>
                    <h5 className="text-sm font-bold text-rose-950">{cluster.name}</h5>
                  </div>
                  <span className="text-xs font-sans font-semibold text-rose-800 px-2.5 py-0.5 rounded bg-rose-100">
                    {cluster.reportCount} Independent Corroborated Reports
                  </span>
                </div>
                <p className="text-xs text-rose-900 leading-relaxed font-sans">
                  {cluster.description}
                </p>
                <div className="flex flex-wrap items-center gap-2 pt-1">
                  {cluster.matchedIndicators.map((ind, idx) => (
                    <span key={idx} className="px-2 py-0.5 rounded bg-white text-xs font-sans text-slate-700 border border-rose-200 flex items-center gap-1.5 shadow-2xs">
                      <AlertTriangle className="w-3 h-3 text-amber-600" />
                      <span>{ind}</span>
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filter Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-200 pb-3">
        {[
          { id: 'ALL', label: 'All Experiences', count: sources.length },
          { id: 'FRAUD', label: 'Fraud Reports', count: fraudCount },
          { id: 'PAYMENT', label: 'Payment Demands', count: paymentCount },
          { id: 'RECRUITER', label: 'Recruiter & Domain', count: sources.filter(s => s.matchedEntities?.some(m => m.includes('EMAIL') || m.includes('DOMAIN')) || (s as any).matchedEntity === 'RECRUITER_EMAIL' || (s as any).matchedEntity === 'DOMAIN').length },
          { id: 'WARNINGS', label: 'Official Notices', count: warningCount },
          { id: 'POSITIVE', label: 'Positive Signals', count: positiveCount },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveFilter(tab.id)}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-sans font-medium transition-colors flex items-center gap-2 cursor-pointer ${
              activeFilter === tab.id
                ? 'bg-blue-600 text-white shadow-xs'
                : 'bg-white text-slate-600 hover:text-slate-900 border border-slate-200 hover:bg-slate-50'
            }`}
          >
            <span>{tab.label}</span>
            <span className={`px-1.5 py-0.2 rounded text-[10px] ${
              activeFilter === tab.id ? 'bg-white/20 text-white font-bold' : 'bg-slate-100 text-slate-600'
            }`}>
              {tab.count}
            </span>
          </button>
        ))}
      </div>

      {/* Sources List */}
      {filteredSources.length === 0 ? (
        <div className="p-8 rounded-xl bg-white border border-slate-200 text-center space-y-3 shadow-xs">
          <Shield className="w-8 h-8 text-slate-400 mx-auto" />
          <h4 className="text-sm font-semibold text-slate-900">No matching public reports in this category</h4>
          <p className="text-xs text-slate-500 max-w-md mx-auto leading-relaxed font-sans">
            Public forum queries returned no records matching the selected filter for {companyName}.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredSources.map((source, idx) => {
            const isScam = source.experienceType.includes('SCAM') || source.experienceType.includes('FRAUD') || source.experienceType.includes('PAYMENT');
            const isAdvisory = source.experienceType.includes('OFFICIAL') || source.experienceType.includes('WARNING');
            const isPositive = source.experienceType.includes('POSITIVE');

            return (
              <div
                key={idx}
                className="p-5 rounded-xl bg-white border border-slate-200 shadow-xs hover:border-blue-300 transition-all space-y-3"
              >
                {/* Header with Badges */}
                <div className="flex items-center justify-between gap-2">
                  <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-sans text-[10px] font-semibold border border-slate-200">
                    {source.sourceTier === 'TIER_1' ? 'TIER 1 · REGULATORY' : source.sourceTier === 'TIER_2' ? 'TIER 2 · PRESS' : 'TIER 3 · COMMUNITY'}
                  </span>

                  <span className={`px-2 py-0.5 rounded text-[10px] font-sans font-medium ${
                    isScam
                      ? 'bg-rose-50 text-rose-700 border border-rose-200'
                      : isAdvisory
                      ? 'bg-amber-50 text-amber-700 border border-amber-200'
                      : isPositive
                      ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                      : 'bg-slate-50 text-slate-600 border border-slate-200'
                  }`}>
                    {source.experienceType.replace(/_/g, ' ')}
                  </span>
                </div>

                {/* Title & External Link */}
                <div className="space-y-1">
                  <a
                    href={source.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm font-semibold text-slate-900 hover:text-blue-600 transition-colors flex items-start justify-between gap-2 group"
                  >
                    <span>{source.title}</span>
                    <ExternalLink className="w-3.5 h-3.5 text-slate-400 group-hover:text-blue-600 shrink-0 mt-0.5" />
                  </a>
                  <p className="text-[11px] font-sans text-slate-500">
                    Publisher: <strong className="text-slate-700">{source.publisher || 'Public Web Source'}</strong> · Matched: <span className="text-blue-600">{source.matchedEntities?.join(', ') || (source as any).matchedEntity || 'Entity'}</span>
                  </p>
                </div>

                {/* Excerpt */}
                <p className="text-xs text-slate-700 leading-relaxed bg-slate-50 p-3 rounded-lg border border-slate-200 font-sans italic">
                  "{source.evidenceText}"
                </p>

                {/* Matching rationale */}
                {(source.matchRationale || (source as any).whyItMatches) && (
                  <p className="text-[11px] text-slate-500 font-sans">
                    <strong className="text-slate-700">Correlation:</strong> {source.matchRationale || (source as any).whyItMatches}
                  </p>
                )}

                {/* Footer Metadata */}
                <div className="flex items-center justify-between text-[10px] font-sans text-slate-500 pt-2 border-t border-slate-100">
                  <span>Status: <strong className="text-slate-700">{source.status || (source as any).sourceStatus || 'LIVE'}</strong></span>
                  <span>Relevance: <strong className="text-blue-700">{Math.round(source.relevance * 100)}%</strong></span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
