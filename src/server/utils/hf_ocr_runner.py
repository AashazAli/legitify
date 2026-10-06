#!/usr/bin/env python3
"""
LEGITIFY Hugging Face OCR Runner
Executes live inference against:
1. pszemraj/pdf-ocr (docTR) for PDFs
2. baidu/Unlimited-OCR for Images/PDFs
Returns structured JSON to stdout.
"""
import sys
import os
import json
import traceback

def run_pdf_ocr(file_path: str, hf_token: str):
    try:
        from gradio_client import Client, handle_file
        os.environ['HF_TOKEN'] = hf_token
        client = Client('pszemraj/pdf-ocr')
        result = client.predict(
            pdf_obj=handle_file(file_path),
            api_name='/convert_PDF'
        )
        if isinstance(result, (list, tuple)) and len(result) > 0:
            raw_text = result[0] if result[0] else ''
            if "File is not a PDF file" in raw_text or len(raw_text.strip()) < 10:
                return {"status": "FAILED", "error": "Insufficient or invalid OCR response", "engine": "PSZEMRAJ_DOCTR"}
            return {
                "status": "SUCCESS",
                "text": raw_text.strip(),
                "engine": "PSZEMRAJ_DOCTR",
                "model": "pszemraj/pdf-ocr",
                "raw_result": str(result[1]) if len(result) > 1 else None
            }
        return {"status": "FAILED", "error": "Unexpected return format from pszemraj/pdf-ocr", "engine": "PSZEMRAJ_DOCTR"}
    except Exception as e:
        return {"status": "FAILED", "error": str(e), "engine": "PSZEMRAJ_DOCTR"}

def run_image_ocr(file_path: str, hf_token: str):
    try:
        from gradio_client import Client, handle_file
        os.environ['HF_TOKEN'] = hf_token
        client = Client('baidu/Unlimited-OCR')
        result = client.predict(
            image_path=handle_file(file_path),
            mode='gundam',
            prompt='document parsing.',
            api_name='/run_ocr'
        )
        if isinstance(result, dict):
            text = result.get('text', '')
            if text and not text.startswith("error:"):
                return {
                    "status": "SUCCESS",
                    "text": text.strip(),
                    "engine": "BAIDU_UNLIMITED_OCR",
                    "model": "baidu/Unlimited-OCR"
                }
            return {"status": "FAILED", "error": text, "engine": "BAIDU_UNLIMITED_OCR"}
        elif isinstance(result, str):
            return {
                "status": "SUCCESS",
                "text": result.strip(),
                "engine": "BAIDU_UNLIMITED_OCR",
                "model": "baidu/Unlimited-OCR"
            }
        return {"status": "FAILED", "error": "Unexpected format from baidu/Unlimited-OCR", "engine": "BAIDU_UNLIMITED_OCR"}
    except Exception as e:
        return {"status": "FAILED", "error": str(e), "engine": "BAIDU_UNLIMITED_OCR"}

def main():
    if len(sys.argv) < 3:
        print(json.dumps({"status": "FAILED", "error": "Usage: hf_ocr_runner.py <pdf|image> <file_path> [hf_token]"}))
        sys.exit(1)

    mode = sys.argv[1].lower()
    file_path = sys.argv[2]
    hf_token = sys.argv[3] if len(sys.argv) > 3 else os.environ.get('HF_TOKEN', '')

    if not os.path.exists(file_path):
        print(json.dumps({"status": "FAILED", "error": f"File not found: {file_path}"}))
        sys.exit(1)

    if mode == 'pdf':
        res = run_pdf_ocr(file_path, hf_token)
        # If pdf-ocr failed or returned empty, try baidu fallback
        if res.get('status') != 'SUCCESS':
            fallback_res = run_image_ocr(file_path, hf_token)
            if fallback_res.get('status') == 'SUCCESS':
                res = fallback_res
    else:
        res = run_image_ocr(file_path, hf_token)

    print(json.dumps(res))

if __name__ == '__main__':
    main()
