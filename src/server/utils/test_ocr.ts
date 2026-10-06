import { createWorker } from 'tesseract.js';
import fs from 'fs';

async function main() {
  console.log('Initializing Tesseract worker...');
  const worker = await createWorker('eng', 1, {
    logger: m => {
      if (m.status === 'recognizing text') console.log(`Progress: ${(m.progress * 100).toFixed(0)}%`);
    }
  });
  
  const imgPath = 'C:/Users/Priya/.gemini/antigravity/brain/110b1791-400d-4384-b7fa-03248cb226df/.user_uploaded/media_1786996634106.jpg';
  console.log('Reading image file...');
  const buf = fs.readFileSync(imgPath);
  
  console.log('Recognizing text...');
  const res = await worker.recognize(buf);
  console.log('=== OCR TEXT EXTRACTED ===\n' + res.data.text);
  await worker.terminate();
}

main().catch(console.error);
