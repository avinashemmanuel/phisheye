from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import os
import re
from urllib.parse import urlparse

# Import only the load_phishing_model function from ml_model.py
from ml_model import load_phishing_model

# Pydantic model for request body
class URLScanRequest(BaseModel):
    url: str

app = FastAPI(
    title="PhishEye Detector API",
    description="API for detecting phishing URLs.",
    version="0.1.0"
)

# --- CORS Configuration ---
origins = [
    "http://localhost",
    "http://localhost:3000",
    "http://127.0.0.1:8000",
    # For browser extensions, you might need to allow specific extension IDs or use '*' for development
    # WARNING: Use specific origins in production!
    "chrome-extension://*",
    "moz-extension://*",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For development, allow all origins. REFINE THIS FOR PRODUCTION!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Feature Extraction Functions (duplicated for clarity and self-containment for prediction) ---
# These functions must be IDENTICAL to those used during training!
# They are not directly used by the pipeline in this setup, but are good for reference
# if you were to add more numerical features to the pipeline.
def get_domain(url):
    try:
        return urlparse(url).netloc
    except:
        return None

def get_path(url):
    try:
        return urlparse(url).path
    except:
        return None

def get_query(url):
    try:
        return urlparse(url).query
    except:
        return None

def having_ip_address(url):
    match = re.search(
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
        r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'  # IPv4
        r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)|'  # IPv4 in hexadecimal
        r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        r'([0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F0-9]{1,4}|'
        r'([0-9a-fA-F]{1,4}:){1,6}:([0-9a-fA-F0-9]{1,4}){1,2}|'
        r'([0-9a-fA-F]{1,4}:){1,5}(:([0-9a-fA-F0-9]{1,4}){1,3}){1,2}|'
        r'([0-9a-fA-F]{1,4}:){1,4}(:([0-9a-fA-F0-9]{1,4}){1,4}){1,2}|'
        r'([0-9a-fA-F]{1,4}:){1,3}(:([0-9a-fA-F0-9]{1,4}){1,5}){1,2}|'
        r'([0-9a-fA-F]{1,4}:){1,2}(:([0-9a-fA-F0-9]{1,4}){1,6}){1,2}|'
        r':((:([0-9a-fA-F0-9]{1,4}){1,7})|:)|'
        r'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'
        r'::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)|'
        r'([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?))'
        , url)
    return 1 if match else 0

def url_length(url):
    return len(url)

def having_at_symbol(url):
    return 1 if "@" in url else 0

def having_double_slash(url):
    return 1 if "//" in url else 0

def count_dots(url):
    return url.count('.')

def count_hyphens(url):
    return url.count('-')

def count_subdomains(url):
    domain = get_domain(url)
    if domain:
        return len(domain.split('.')) - 1
    return 0
# --- END Feature Extraction Functions ---

# --- FastAPI Event Handlers ---
@app.on_event("startup")
async def startup_event():
    # Load the model and assign it to app.state
    app.state.phishing_detector_model = load_phishing_model()
    print("FastAPI app startup: ML model loaded and assigned to app.state.")

@app.on_event("shutdown")
async def shutdown_event():
    print("FastAPI app shutdown.")
    # Any cleanup can go here

# --- API Endpoints ---
@app.get("/")
async def read_root():
    return {"message": "Welcome to PhishEye Detector API!"}

@app.get("/health")
async def health_check():
    if not hasattr(app.state, 'phishing_detector_model') or app.state.phishing_detector_model is None:
        return {"status": "error", "message": "ML model not loaded."}
    return {"status": "ok", "message": "API is healthy and ML model is loaded."}

@app.post("/scan_url")
async def scan_url(request: URLScanRequest):
    url = request.url

    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
    
    if not hasattr(app.state, 'phishing_detector_model') or app.state.phishing_detector_model is None:
        raise HTTPException(status_code=500, detail="ML model is not loaded yet.")

    try:
        # The pipeline expects a list of URLs
        prediction = app.state.phishing_detector_model.predict([url])[0]
        prediction_proba = app.state.phishing_detector_model.predict_proba([url])[0]

        status = "Safe"
        confidence = prediction_proba[0] # Confidence for 'good'
        if prediction == 1: # 'bad'
            status = "Dangerous"
            confidence = prediction_proba[1] # Confidence for 'bad'
        elif confidence < 0.8: # Example threshold for 'Suspicious'
            status = "Suspicious"

        return {
            "url": url,
            "status": status,
            "confidence": round(confidence, 4),
            "prediction_raw": int(prediction) # 0 for good, 1 for bad
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during URL scan: {str(e)}")

# No if __name__ == "__main__": block here.
# Run with: uvicorn main:app --reload --host 0.0.0.0 --port 8000