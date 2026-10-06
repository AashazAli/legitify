"""
High-Speed Local Python OCR Runner for LEGITIFY
Resizes large images with Pillow for sub-2-second CPU inference
"""
import sys
import json
import os
import warnings
warnings.filterwarnings('ignore')
os.environ['PYTHONWARNINGS'] = 'ignore'
from PIL import Image
import easyocr

_reader = None

def get_reader():
    global _reader
    if _reader is None:
        _reader = easyocr.Reader(['en'], gpu=False, verbose=False)
    return _reader

def extract_text(image_path: str) -> str:
    try:
        # Pre-process image to speed up CPU inference dramatically
        img = Image.open(image_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Scale down if larger than 1280 on any dimension
        max_dim = max(img.size)
        if max_dim > 1280:
            scale = 1280.0 / max_dim
            new_size = (int(img.size[0] * scale), int(img.size[1] * scale))
            img = img.resize(new_size, Image.Resampling.LANCZOS)
        
        # Save temporary optimized image
        opt_path = image_path + "_opt.jpg"
        img.save(opt_path, "JPEG", quality=85)
        
        reader = get_reader()
        results = reader.readtext(opt_path, detail=0)
        
        try:
            if os.path.exists(opt_path):
                os.remove(opt_path)
        except:
            pass
            
        return "\n".join(results)
    except Exception as e:
        sys.stderr.write(f"OCR Error: {e}\n")
        return ""

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No image path provided", "text": ""}))
        sys.exit(1)
    
    img_path = sys.argv[1]
    extracted = extract_text(img_path)
    output = {
        "text": extracted,
        "length": len(extracted)
    }
    print(json.dumps(output))
