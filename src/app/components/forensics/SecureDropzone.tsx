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
    <div className="w-full space-y-3">
      {/* Drop Zone Box */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => !isProcessing && fileInputRef.current?.click()}
        className={`relative rounded-xl border-2 border-dashed transition-all duration-200 cursor-pointer overflow-hidden p-8 text-center select-none ${
          isDragOver
            ? 'border-blue-500 bg-blue-50/50 ring-2 ring-blue-500/20'
            : isProcessing
            ? 'border-slate-300 bg-slate-50 cursor-not-allowed'
            : 'border-slate-300 bg-slate-50/70 hover:border-blue-500 hover:bg-blue-50/30'
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
          <div className="py-6 space-y-4">
            <div className="flex items-center justify-center gap-2.5">
              <Cpu className="w-5 h-5 text-blue-600 animate-spin" />
              <span className="font-sans text-sm font-semibold text-slate-800">
                Analyzing Document Structure & Signals
              </span>
            </div>

            <div className="max-w-md mx-auto space-y-2">
              <div className="flex justify-between text-xs font-sans text-slate-600">
                <span>{processingStage || 'Processing file bytes...'}</span>
                <span className="font-semibold text-slate-700">{Math.round(processingProgress * 100)}%</span>
              </div>
              <div className="w-full h-1.5 bg-slate-200 rounded-full overflow-hidden">
                <div
                  className="h-full bg-blue-600 transition-all duration-300"
                  style={{ width: `${Math.round(processingProgress * 100)}%` }}
                />
              </div>
            </div>

            <p className="text-xs text-slate-500">
              Verifying cryptographic hash integrity, layout consistency, and optical markers
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="flex items-center justify-center">
              <div className="w-12 h-12 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600 shadow-sm transition-transform hover:scale-105">
                <Upload className="w-6 h-6" />
              </div>
            </div>

            <div className="space-y-1">
              <h4 className="text-sm font-semibold text-slate-900 tracking-tight">
                Select document or drag and drop
              </h4>
              <p className="text-xs text-slate-500 max-w-md mx-auto">
                Upload offer letters, certificates, or employment contracts for forensic verification.
              </p>
            </div>

            <p className="text-[11px] text-slate-400 pt-1">
              Supports PDF, PNG, JPEG up to 5MB. Client-side SHA-256 integrity verification applied.
            </p>
          </div>
        )}
      </div>

      {/* Security Rejection Banner */}
      {errorMsg && (
        <div className="p-3.5 rounded-lg bg-rose-50 border border-rose-200 flex items-start gap-3">
          <ShieldAlert className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
          <div className="space-y-0.5">
            <h5 className="text-xs font-semibold text-rose-900">
              File Validation Failed
            </h5>
            <p className="text-xs text-rose-700 leading-relaxed">{errorMsg}</p>
          </div>
        </div>
      )}

      {/* Pre-flight Validated File Card */}
      {validatedFile && !isProcessing && (
        <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-sm space-y-3">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2.5">
              <FileCheck className="w-4 h-4 text-emerald-600" />
              <span className="text-xs font-semibold text-slate-900">{validatedFile.file.name}</span>
              <span className="text-[11px] font-sans px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-medium">
                {formatBytes(validatedFile.file.size)}
              </span>
              <span className="text-[11px] font-sans px-2 py-0.5 rounded bg-blue-50 border border-blue-200 text-blue-700 font-semibold">
                {validatedFile.validation.detectedFormat}
              </span>
            </div>

            <div className="flex items-center gap-1.5 text-[11px] font-mono text-slate-500">
              <span>Magic Bytes:</span>
              <span className="text-slate-800 font-semibold">{validatedFile.validation.actualHex}</span>
            </div>
          </div>

          <div className="pt-2 border-t border-slate-100 flex items-center justify-between text-xs font-mono text-slate-500">
            <div className="flex items-center gap-2 truncate max-w-xl">
              <span className="text-slate-400">SHA-256:</span>
              <span className="text-slate-700 truncate">{validatedFile.sha256}</span>
            </div>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                copyHashToClipboard();
              }}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 text-[11px] text-slate-700 font-sans transition-colors cursor-pointer"
            >
              {copiedHash ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
              {copiedHash ? 'Copied' : 'Copy'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
