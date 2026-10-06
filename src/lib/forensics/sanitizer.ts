// ==============================================================================
// LEGITIFY FORENSIC SUITE - CYBERSECURITY SANITIZER
// DOMPurify XSS Hardening & Metadata-Stripped Visual Previews
// ==============================================================================

import DOMPurify from 'dompurify';

/**
 * Strictly sanitizes untrusted text strings to plain text, stripping all HTML tags and script vectors.
 */
export function sanitizeText(untrustedInput: unknown): string {
  if (untrustedInput === null || untrustedInput === undefined) return '';
  const str = String(untrustedInput);
  return DOMPurify.sanitize(str, {
    ALLOWED_TAGS: [],
    ALLOWED_ATTR: [],
    KEEP_CONTENT: true,
  }).trim();
}

/**
 * Sanitizes formatted HTML strings, permitting only harmless text styling tags.
 */
export function sanitizeSafeHtml(untrustedHtml: string): string {
  if (!untrustedHtml) return '';
  return DOMPurify.sanitize(untrustedHtml, {
    ALLOWED_TAGS: ['span', 'b', 'strong', 'i', 'em', 'code', 'mark', 'br'],
    ALLOWED_ATTR: ['class', 'style', 'title'],
  });
}

/**
 * Renders an image into an isolated HTML5 Canvas to completely strip all raw EXIF metadata,
 * polyglot payloads, and malicious script chunks before creating a safe display URL.
 */
export async function createSanitizedImagePreview(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    // For non-images or direct PDFs, return an empty preview or placeholder
    if (file.type === 'application/pdf' || file.name.toLowerCase().endsWith('.pdf')) {
      resolve('');
      return;
    }

    const objectUrl = URL.createObjectURL(file);
    const img = new Image();

    img.crossOrigin = 'anonymous';
    img.onload = () => {
      try {
        // Downscale oversized images for Anti-DoS display memory protection (max 2048px)
        let { width, height } = img;
        const maxDim = 2048;
        if (width > maxDim || height > maxDim) {
          if (width > height) {
            height = Math.round((height * maxDim) / width);
            width = maxDim;
          } else {
            width = Math.round((width * maxDim) / height);
            height = maxDim;
          }
        }

        const canvas = document.createElement('canvas');
        canvas.width = Math.max(1, width);
        canvas.height = Math.max(1, height);
        const ctx = canvas.getContext('2d', { willReadFrequently: true });

        if (!ctx) {
          URL.revokeObjectURL(objectUrl);
          resolve(objectUrl);
          return;
        }

        // Draw image pixels onto clean canvas
        ctx.fillStyle = '#0F172A';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

        // Convert to sanitized clean PNG data URL (pure pixel array, stripped of all original EXIF chunks)
        const cleanDataUrl = canvas.toDataURL('image/png', 0.95);
        URL.revokeObjectURL(objectUrl);
        resolve(cleanDataUrl);
      } catch (err) {
        URL.revokeObjectURL(objectUrl);
        reject(new Error(`Failed to generate sanitized image preview: ${err instanceof Error ? err.message : String(err)}`));
      }
    };

    img.onerror = () => {
      URL.revokeObjectURL(objectUrl);
      reject(new Error('Image decode failed: The file stream is corrupted or invalid.'));
    };

    img.src = objectUrl;
  });
}

/**
 * Formats byte counts into human-readable strings.
 */
export function formatBytes(bytes: number, decimals: number = 2): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}
