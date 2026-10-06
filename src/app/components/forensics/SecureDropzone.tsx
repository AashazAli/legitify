// ==============================================================================
// LEGITIFY FORENSIC SUITE - SECURE DROPZONE COMPONENT
// Strict 5MB Anti-DoS Guard, Hex Magic Byte Validation, Web Crypto Hashing
// ==============================================================================

import React, { useState, useRef, useCallback } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Upload,
  FileCheck,
  AlertTriangle,
  Lock,
  Cpu,
  FileText,
  Binary,
  Copy,
  Check,
} from 'lucide-react';
import { validateMagicNumbers, calculateFileHash, MAX_FILE_SIZE_BYTES } from '../../../lib/forensics/AnalysisEngine';
import { formatBytes } from '../../../lib/forensics/sanitizer';
import { MagicValidationResult } from '../../../lib/forensics/types';

interface SecureDropzoneProps {
  onFileValidated: (file: File, validation: MagicValidationResult, sha256: string) => void;
  isProcessing?: boolean;
  processingStage?: string;
  processingProgress?: number;
}

export const SecureDropzone: React.FC<SecureDropzoneProps> = ({
  onFileValidated,
  isProcessing = false,
  processingStage = '',
  processingProgress = 0,
}) => {
  const [isDragOver, setIsDragOver] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [validatedFile, setValidatedFile] = useState<{
    file: File;
    validation: MagicValidationResult;
    sha256: string;
  } | null>(null);
  const [copiedHash, setCopiedHash] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const processFile = useCallback(
    async (file: File) => {
      setErrorMsg(null);

      // 1. Strict 5MB Size Limit (Anti-DoS)
      if (file.size > MAX_FILE_SIZE_BYTES) {
        setErrorMsg(
          `Security Policy Rejection: File size (${formatBytes(file.size)}) exceeds the strict 5MB resource ceiling.`
        );
        return;
      }

      try {
        // 2. Magic Byte Signature Validation
        const validation = await validateMagicNumbers(file);
        if (!validation.isValid) {
          setErrorMsg(
            validation.errorMessage ||
              `File rejected: Magic bytes [${validation.actualHex}] do not match authorized formats.`
          );
          return;
        }

        // 3. Web Crypto SHA-256 Digest
        const sha256 = await calculateFileHash(file);

        setValidatedFile({ file, validation, sha256 });
        onFileValidated(file, validation, sha256);
      } catch (err: any) {
        setErrorMsg(err?.message || 'Cryptographic validation failed unexpectedly.');
      }
    },
    [onFileValidated]
  );

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (!isProcessing) setIsDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);

    if (isProcessing) return;

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      processFile(e.target.files[0]);
    }
  };

  const copyHashToClipboard = () => {
    if (validatedFile?.sha256) {
      navigator.clipboard.writeText(validatedFile.sha256);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    }
  };

  return (
    <div className="w-full space-y-4">
      {/* Drop Zone Box */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => !isProcessing && fileInputRef.current?.click()}
        className={`relative rounded-md border transition-all duration-200 cursor-pointer overflow-hidden p-8 text-center select-none ${
          isDragOver
            ? 'border-emerald-500 bg-slate-900/90 ring-1 ring-emerald-500'
            : isProcessing
            ? 'border-slate-700 bg-slate-900/60 cursor-not-allowed'
            : 'border-slate-800 bg-slate-950 hover:border-slate-700 hover:bg-slate-900/50'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".png,.jpg,.jpeg,.pdf,.webp,.tiff"
          onChange={handleFileInputChange}
          disabled={isProcessing}
          className="hidden"
        />

        {isProcessing ? (
          <div className="py-6 space-y-5">
            <div className="flex items-center justify-center gap-3">
              <Cpu className="w-5 h-5 text-emerald-400 animate-spin" />
              <span className="font-sans text-sm font-semibold tracking-wide text-slate-200">
                FORENSIC ENGINE ACTIVE
              </span>
            </div>

            <div className="max-w-md mx-auto space-y-2">
              <div className="flex justify-between text-xs font-mono text-slate-400">
                <span>{processingStage || 'Processing file bytes...'}</span>
                <span>{Math.round(processingProgress * 100)}%</span>
              </div>
              <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-emerald-500 transition-all duration-300"
                  style={{ width: `${Math.round(processingProgress * 100)}%` }}
                />
              </div>
            </div>

            <p className="text-xs font-mono text-slate-500">
              Performing SHA-256 chain of custody, EXIF extraction, Canvas pixel variance & Tesseract OCR
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex items-center justify-center">
              <div className="w-12 h-12 rounded-md bg-slate-900 border border-slate-800 flex items-center justify-center text-slate-300 group-hover:text-emerald-400 transition-colors">
                <Upload className="w-6 h-6" />
              </div>
            </div>

            <div className="space-y-1">
              <h4 className="text-sm font-semibold text-slate-100 tracking-tight">
                Drop document or certificate for deterministic forensic inspection
              </h4>
              <p className="text-xs text-slate-400">
                Click to browse or drag file. Validates magic bytes, SHA-256 custody, EXIF tags & pixel variance.
              </p>
            </div>

            <div className="flex flex-wrap items-center justify-center gap-2 pt-2">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-400">
                <Lock className="w-3 h-3 text-emerald-400" />
                Anti-DoS: Max 5MB
              </span>
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-400">
                <Binary className="w-3 h-3 text-teal-400" />
                Magic Bytes: PNG · JPEG · PDF
              </span>
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-400">
                <ShieldCheck className="w-3 h-3 text-emerald-400" />
                Web Crypto SHA-256
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Security Rejection Banner */}
      {errorMsg && (
        <div className="p-4 rounded-md bg-rose-950/40 border border-rose-900/80 flex items-start gap-3">
          <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <h5 className="text-xs font-semibold text-rose-200 tracking-wide uppercase">
              Cybersecurity Security Violation
            </h5>
            <p className="text-xs text-rose-300 font-mono leading-relaxed">{errorMsg}</p>
          </div>
        </div>
      )}

      {/* Pre-flight Validated File Card */}
      {validatedFile && !isProcessing && (
        <div className="p-4 rounded-md bg-slate-900/70 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2.5">
              <FileCheck className="w-4 h-4 text-emerald-400" />
              <span className="text-xs font-semibold text-slate-200">{validatedFile.file.name}</span>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                {formatBytes(validatedFile.file.size)}
              </span>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-800 text-emerald-300">
                {validatedFile.validation.detectedFormat}
              </span>
            </div>

            <div className="flex items-center gap-1.5 text-[11px] font-mono text-slate-400">
              <span>Magic Bytes:</span>
              <span className="text-slate-200 font-semibold">{validatedFile.validation.actualHex}</span>
            </div>
          </div>

          <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono text-slate-400">
            <div className="flex items-center gap-2 truncate max-w-xl">
              <span className="text-slate-500">SHA-256:</span>
              <span className="text-slate-300 truncate">{validatedFile.sha256}</span>
            </div>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                copyHashToClipboard();
              }}
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-[11px] text-slate-300 transition-colors"
            >
              {copiedHash ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              {copiedHash ? 'Copied' : 'Copy'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
