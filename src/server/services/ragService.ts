// ==============================================================================
// LEGITIFY DECOUPLED DUAL RAG RETRIEVAL SERVICE
// Logically separates DOCUMENT_RAG from EXTERNAL_EVIDENCE_RAG
// ==============================================================================
import { RAGKnowledgeChunk, EvidenceItem } from '../../types';

export interface DocumentRAGChunk {
  chunk_id: string; // [Doc-P{page}-C{index}]
  page: number;
  text: string;
  source_type: 'DOCUMENT_TEXT' | 'DOCUMENT_OCR' | 'DOCUMENT_VISUAL';
  relevance_score?: number;
}

export interface ExternalEvidenceRAGChunk {
  chunk_id: string; // [Ext-{source}-{id}]
  source: string;
  source_type: string;
  url?: string;
  authority_tier: number; // 1 (Official) to 5 (Unverified)
  claim: string;
  evidence_text: string;
  retrieved_at: string;
  claim_state: 'VERIFIED_EXTERNALLY' | 'OBSERVED_BY_AI' | 'CONTRADICTED' | 'UNVERIFIED' | 'UNAVAILABLE';
  relevance_score?: number;
}

export interface DualRAGStore {
  scanId: string;
  documentChunks: DocumentRAGChunk[];
  externalChunks: ExternalEvidenceRAGChunk[];
}

// In-memory dual RAG stores indexed by scanId
const SCAN_RAG_REGISTRY = new Map<string, DualRAGStore>();

/**
 * Indexes chunks from the uploaded document into DOCUMENT_RAG
 */
export function indexDocumentChunks(
  scanId: string,
  rawText: string,
  pages?: { page: number; text: string }[]
): DocumentRAGChunk[] {
  const store = getOrCreateStore(scanId);
  store.documentChunks = [];

  if (pages && pages.length > 0) {
    for (const p of pages) {
      const paragraphs = p.text.split(/\n{2,}/).map(t => t.trim()).filter(t => t.length > 20);
      paragraphs.forEach((para, idx) => {
        store.documentChunks.push({
          chunk_id: `Doc-P${p.page}-C${idx}`,
          page: p.page,
          text: para,
          source_type: 'DOCUMENT_TEXT',
        });
      });
    }
  } else {
    // Single page / linear text chunking
    const paragraphs = rawText.split(/\n{2,}/).map(t => t.trim()).filter(t => t.length > 20);
    if (paragraphs.length === 0 && rawText.trim().length > 0) {
      paragraphs.push(rawText.trim());
    }
    paragraphs.forEach((para, idx) => {
      store.documentChunks.push({
        chunk_id: `Doc-P1-C${idx}`,
        page: 1,
        text: para,
        source_type: 'DOCUMENT_TEXT',
      });
    });
  }

  return store.documentChunks;
}

/**
 * Indexes normalized external intelligence into EXTERNAL_EVIDENCE_RAG
 */
export function indexExternalEvidence(
  scanId: string,
  evidenceItems: EvidenceItem[]
): ExternalEvidenceRAGChunk[] {
  const store = getOrCreateStore(scanId);
  store.externalChunks = [];

  evidenceItems.forEach((item, idx) => {
    const src = (item.source_name || item.category || 'EXT').toUpperCase().replace(/[^A-Z0-9]/g, '');
    const chunkId = `Ext-${src}-${String(idx + 1).padStart(2, '0')}`;
    
    let tier = 3;
    if (item.category === 'COMPANY' || item.category === 'REGISTRY') tier = 1;
    else if (item.category === 'DOMAIN' || item.category === 'THREAT') tier = 2;
    else if (item.category === 'EMAIL' || item.category === 'PUBLIC_REPORT') tier = 4;

    store.externalChunks.push({
      chunk_id: chunkId,
      source: item.source_name || 'External Investigation',
      source_type: item.category || 'EXTERNAL',
      url: item.source_url || (item as any).url,
      authority_tier: tier,
      claim: item.title || '',
      evidence_text: item.evidence_text || item.snippet || '',
      retrieved_at: (item as any).retrieved_at || item.collected_at || new Date().toISOString(),
      claim_state: item.verified ? 'VERIFIED_EXTERNALLY' : 'UNVERIFIED',
    });
  });

  return store.externalChunks;
}

/**
 * Dual RAG Retrieval: Retrieves relevant chunks from both Document RAG and External RAG
 */
export function retrieveDualRAG(
  scanId: string,
  query: string
): {
  documentCitations: DocumentRAGChunk[];
  externalCitations: ExternalEvidenceRAGChunk[];
  formattedContext: string;
} {
  const store = getOrCreateStore(scanId);
  const qTerms = query.toLowerCase().split(/\s+/).filter(w => w.length > 2);

  // 1. Search Document RAG
  const docMatches = store.documentChunks.map(chunk => {
    let matches = 0;
    const lower = chunk.text.toLowerCase();
    for (const term of qTerms) {
      if (lower.includes(term)) matches++;
    }
    return { ...chunk, relevance_score: matches };
  })
  .filter(c => (c.relevance_score || 0) > 0)
  .sort((a, b) => (b.relevance_score || 0) - (a.relevance_score || 0))
  .slice(0, 4);

  // 2. Search External Evidence RAG
  const extMatches = store.externalChunks.map(chunk => {
    let matches = 0;
    const lower = `${chunk.claim} ${chunk.evidence_text} ${chunk.source}`.toLowerCase();
    for (const term of qTerms) {
      if (lower.includes(term)) matches++;
    }
    return { ...chunk, relevance_score: matches };
  })
  .filter(c => (c.relevance_score || 0) > 0)
  .sort((a, b) => (b.relevance_score || 0) - (a.relevance_score || 0))
  .slice(0, 4);

  // 3. Construct clean dual citations block
  const docLines = docMatches.map(d => `[${d.chunk_id}] (Page ${d.page}): "${d.text.slice(0, 200)}..."`);
  const extLines = extMatches.map(e => `[${e.chunk_id}] (Source: ${e.source}, State: ${e.claim_state}): ${e.claim} — ${e.evidence_text.slice(0, 200)}...`);

  let formatted = '';
  if (docLines.length > 0) {
    formatted += `### Document Evidence Citations (DOCUMENT_RAG):\n${docLines.join('\n')}\n\n`;
  }
  if (extLines.length > 0) {
    formatted += `### External Authoritative Citations (EXTERNAL_EVIDENCE_RAG):\n${extLines.join('\n')}`;
  }

  return {
    documentCitations: docMatches,
    externalCitations: extMatches,
    formattedContext: formatted.trim(),
  };
}

function getOrCreateStore(scanId: string): DualRAGStore {
  const existing = SCAN_RAG_REGISTRY.get(scanId);
  if (existing) return existing;
  const created: DualRAGStore = {
    scanId,
    documentChunks: [],
    externalChunks: [],
  };
  SCAN_RAG_REGISTRY.set(scanId, created);
  return created;
}

// Backward-compatible adapter for existing calls
export function retrieveRAGKnowledge(query: {
  entityName?: string;
  domain?: string;
  email?: string;
  hasFeeDemand?: boolean;
  contextText?: string;
  scanId?: string;
}): { chunks: RAGKnowledgeChunk[]; summary: string } {
  const scanId = query.scanId || 'default-scan';
  const qStr = `${query.entityName || ''} ${query.domain || ''} ${query.email || ''} ${query.contextText || ''}`.trim();
  const dual = retrieveDualRAG(scanId, qStr || 'internship job offer verification');

  const chunks: RAGKnowledgeChunk[] = [];
  dual.documentCitations.forEach(d => {
    chunks.push({
      document_id: d.chunk_id,
      chunk_id: d.chunk_id,
      title: `Document Page ${d.page}`,
      content: d.text,
      source: 'Uploaded Offer Document',
      source_type: 'DOCUMENT_UPLOAD',
      authority_level: 'TIER_2_HIGH_QUALITY',
    });
  });
  dual.externalCitations.forEach(e => {
    chunks.push({
      document_id: e.chunk_id,
      chunk_id: e.chunk_id,
      title: e.claim,
      content: e.evidence_text,
      source: e.source,
      source_type: e.source_type,
      authority_level: e.authority_tier === 1 ? 'TIER_1_AUTHORITATIVE' : 'TIER_2_HIGH_QUALITY',
    });
  });

  return {
    chunks,
    summary: dual.formattedContext || 'No matching document or external evidence chunks retrieved.',
  };
}
