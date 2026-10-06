import React, { useState } from 'react';
import { Shield, AlertTriangle, ExternalLink, RefreshCw, CheckCircle, Search, Filter, Layers } from 'lucide-react';
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
    <div className="space-y-6">
      {/* Header with Title, Status Badges, and Re-Investigate Action */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-3xl bg-[#0D1117] border-2 border-[#1E2838] shadow-2xl">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <span className="text-2xl">🌐</span>
            <h3 className="text-xl font-black text-slate-100 text-glow-cyan">
              Real-Time Public Experience & Complaint Intelligence
            </h3>
          </div>
          <p className="text-xs text-slate-400 font-mono">
            Query-driven investigation of candidate reports across Reddit, consumer forums & corporate caution notices
          </p>
          <div className="flex flex-wrap items-center gap-2 pt-2">
            <span className={`px-3 py-1 rounded-full text-[11px] font-mono font-bold uppercase tracking-wider ${
              isLive
                ? 'bg-emerald-500/20 text-[#00FF87] border border-emerald-500/40'
                : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
            }`}>
              {isLive ? '🟢 LIVE INVESTIGATION' : '🟡 CACHED EVIDENCE'}
            </span>
            <span className="text-xs font-mono text-slate-400">
              Retrieved: {searchTimestamp ? new Date(searchTimestamp).toLocaleTimeString() : new Date().toLocaleTimeString()}
            </span>
            {data?.investigationId && (
              <span className="text-[11px] font-mono text-slate-400">
                · ID: <strong className="text-[#00F0FF]">{data.investigationId}</strong>
              </span>
            )}
          </div>
        </div>

        {onReinvestigate && (
          <button
            onClick={handleReinvestigateClick}
            disabled={isReinvestigating}
            className={`px-5 py-3 rounded-2xl font-black text-xs font-mono tracking-wider uppercase transition-all flex items-center gap-2.5 cursor-pointer shadow-lg ${
              isReinvestigating
                ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                : 'bg-[#131822] hover:bg-[#1E2838] text-[#00FF87] border border-[#00FF87]/40 hover:border-[#00FF87] shadow-[0_0_15px_rgba(0,255,135,0.15)]'
            }`}
          >
            <RefreshCw className={`w-4 h-4 ${isReinvestigating ? 'animate-spin' : ''}`} />
            <span>{isReinvestigating ? 'Investigating Live...' : 'Investigate Again'}</span>
          </button>
        )}
      </div>

      {reinvestigateError && (
        <div className="p-4 rounded-2xl bg-red-500/10 border border-red-500/30 text-xs font-mono text-red-300 flex items-center gap-3">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{reinvestigateError}</span>
        </div>
      )}

      {/* Summary Metrics Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <div className="p-4 rounded-2xl bg-[#0D1117] border border-[#1E2838] text-center">
          <span className="text-2xl font-black text-slate-100">{sources.length}</span>
          <span className="text-[10px] font-mono uppercase text-slate-400 block mt-1">Sources Evaluated</span>
        </div>
        <div className="p-4 rounded-2xl bg-[#0D1117] border border-red-500/30 text-center">
          <span className="text-2xl font-black text-red-400">{fraudCount}</span>
          <span className="text-[10px] font-mono uppercase text-red-400/80 block mt-1">Fraud Reports</span>
        </div>
        <div className="p-4 rounded-2xl bg-[#0D1117] border border-orange-500/30 text-center">
          <span className="text-2xl font-black text-orange-400">{paymentCount}</span>
          <span className="text-[10px] font-mono uppercase text-orange-400/80 block mt-1">Payment Demands</span>
        </div>
        <div className="p-4 rounded-2xl bg-[#0D1117] border border-amber-500/30 text-center">
          <span className="text-2xl font-black text-amber-300">{warningCount}</span>
          <span className="text-[10px] font-mono uppercase text-amber-300/80 block mt-1">Caution Notices</span>
        </div>
        <div className="p-4 rounded-2xl bg-[#0D1117] border border-emerald-500/30 text-center col-span-2 sm:col-span-1">
          <span className="text-2xl font-black text-[#00FF87]">{positiveCount}</span>
          <span className="text-[10px] font-mono uppercase text-emerald-400/80 block mt-1">Positive Signals</span>
        </div>
      </div>

      {/* Real-Source Integrity & Provider Audit Bar */}
      {providers.length > 0 && (
        <div className="p-4 rounded-2xl bg-[#0A0D14] border border-[#1E2838] flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-2 text-slate-400">
            <Shield className="w-4 h-4 text-[#00FF87]" />
            <span className="font-bold">Real-Source Integrity Audit:</span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {providers.map((p, i) => (
              <span
                key={i}
                className={`px-2.5 py-1 rounded-full text-[10px] font-mono font-bold flex items-center gap-1.5 ${
                  p.status === 'LIVE'
                    ? 'bg-emerald-500/10 text-[#00FF87] border border-emerald-500/30'
                    : p.status === 'NOT_FOUND'
                    ? 'bg-slate-800 text-slate-400 border border-slate-700'
                    : 'bg-amber-500/10 text-amber-300 border border-amber-500/30'
                }`}
              >
                <span>{p.status === 'LIVE' ? '●' : p.status === 'NOT_FOUND' ? '○' : '▲'}</span>
                <span>{p.provider}: {p.status} {(p as any).recordsReturned !== undefined || (p as any).resultCount !== undefined ? `(${(p as any).recordsReturned ?? (p as any).resultCount} found)` : ''}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Complaint Clusters (Toxic Multi-Signal Correlation) */}
      {clusters.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-red-400" />
            <h4 className="text-sm font-black text-slate-200 uppercase font-mono tracking-wider">
              Corroborated Fraud Clusters Detected ({clusters.length})
            </h4>
          </div>
          <div className="grid grid-cols-1 gap-4">
            {clusters.map((cluster, i) => (
              <div
                key={i}
                className="p-5 rounded-2xl bg-red-500/10 border-2 border-red-500/40 space-y-3 shadow-xl"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <span className="px-2.5 py-1 rounded-md bg-red-500/20 text-red-400 font-mono font-black text-xs">
                      {cluster.clusterId}
                    </span>
                    <h5 className="text-base font-black text-slate-100">{cluster.name}</h5>
                  </div>
                  <span className="text-xs font-mono font-bold text-red-300 px-3 py-1 rounded-full bg-red-500/20">
                    {cluster.reportCount} Independent Candidate Reports
                  </span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed font-semibold">
                  {cluster.description}
                </p>
                <div className="flex flex-wrap items-center gap-2 pt-1">
                  {cluster.matchedIndicators.map((ind, idx) => (
                    <span key={idx} className="px-2.5 py-0.5 rounded-full bg-[#131822] text-xs font-mono text-slate-300 border border-[#1E2838]">
                      ⚠️ {ind}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filter Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b border-[#1E2838] pb-3">
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
            className={`px-4 py-2 rounded-xl text-xs font-mono font-bold transition-all flex items-center gap-2 cursor-pointer ${
              activeFilter === tab.id
                ? 'bg-[#00FF87] text-black shadow-[0_0_15px_rgba(0,255,135,0.3)]'
                : 'bg-[#0D1117] text-slate-400 hover:text-slate-200 border border-[#1E2838]'
            }`}
          >
            <span>{tab.label}</span>
            <span className={`px-1.5 py-0.2 rounded-md text-[10px] ${
              activeFilter === tab.id ? 'bg-black/20 text-black' : 'bg-[#1E2838] text-slate-400'
            }`}>
              {tab.count}
            </span>
          </button>
        ))}
      </div>

      {/* Sources List */}
      {filteredSources.length === 0 ? (
        <div className="p-8 rounded-3xl bg-[#0D1117] border-2 border-[#1E2838] text-center space-y-3">
          <span className="text-3xl">🛡️</span>
          <h4 className="text-base font-black text-slate-100">No matching public reports in this category</h4>
          <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
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
                className={`p-5 rounded-2xl bg-[#0D1117] border-2 transition-all space-y-3 shadow-xl ${
                  isScam
                    ? 'border-red-500/40 hover:border-red-500/70'
                    : isAdvisory
                    ? 'border-amber-500/40 hover:border-amber-500/70'
                    : isPositive
                    ? 'border-emerald-500/40 hover:border-emerald-500/70'
                    : 'border-[#1E2838] hover:border-slate-700'
                }`}
              >
                {/* Header with Badges */}
                <div className="flex items-center justify-between gap-2">
                  <span className={`px-2.5 py-1 rounded-full text-[10px] font-mono font-black uppercase tracking-wider ${
                    source.sourceTier === 'TIER_1'
                      ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                      : source.sourceTier === 'TIER_2'
                      ? 'bg-blue-500/20 text-blue-300 border border-blue-500/40'
                      : 'bg-slate-800 text-slate-300 border border-slate-700'
                  }`}>
                    {source.sourceTier === 'TIER_1' ? '🏛️ TIER 1: OFFICIAL' : source.sourceTier === 'TIER_2' ? '📰 TIER 2: MEDIA' : '💬 TIER 3: FORUM'}
                  </span>

                  <span className={`px-2.5 py-1 rounded-full text-[10px] font-mono font-bold ${
                    isScam
                      ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                      : isAdvisory
                      ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                      : isPositive
                      ? 'bg-emerald-500/20 text-[#00FF87] border border-emerald-500/40'
                      : 'bg-slate-800 text-slate-400 border border-slate-700'
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
                    className="text-sm font-black text-slate-100 hover:text-[#00FF87] transition-colors flex items-start justify-between gap-2 group"
                  >
                    <span>{source.title}</span>
                    <ExternalLink className="w-3.5 h-3.5 text-slate-500 group-hover:text-[#00FF87] shrink-0 mt-0.5" />
                  </a>
                  <p className="text-[11px] font-mono text-slate-400">
                    Publisher: <strong className="text-slate-300">{source.publisher || 'Public Web Source'}</strong> · Matched: <span className="text-[#00F0FF]">{source.matchedEntities?.join(', ') || (source as any).matchedEntity || 'Entity'}</span>
                  </p>
                </div>

                {/* Excerpt */}
                <p className="text-xs text-slate-300 leading-relaxed bg-[#131822] p-3 rounded-xl border border-[#1E2838] font-mono">
                  "{source.evidenceText}"
                </p>

                {/* Matching rationale */}
                {(source.matchRationale || (source as any).whyItMatches) && (
                  <p className="text-[11px] text-slate-400 font-mono">
                    🎯 <strong>Correlation:</strong> {source.matchRationale || (source as any).whyItMatches}
                  </p>
                )}

                {/* Footer Metadata */}
                <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 pt-1 border-t border-[#1E2838]">
                  <span>Status: <strong className="text-slate-300">{source.status || (source as any).sourceStatus || 'LIVE'}</strong></span>
                  <span>Relevance: <strong className="text-[#00FF87]">{Math.round(source.relevance * 100)}%</strong></span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
