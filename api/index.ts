import type { IncomingMessage, ServerResponse } from 'http';
import app from '../src/server/index';

// Vercel Serverless Function Handler (Exact Localhost Express Engine)
export default function handler(req: IncomingMessage & { url?: string }, res: ServerResponse) {
  if (req.url) {
    const matched = req.headers['x-matched-path'] as string;
    if (matched && matched.startsWith('/api')) {
      req.url = matched;
    }
  }
  return app(req as any, res as any);
}
