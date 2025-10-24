from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import joblib
import re
import numpy as np
from urllib.parse import urlparse # Still useful for basic validation, but not for model features

app = FastAPI()

# Configure CORS
origins = [
    "http://localhost",
    "http://localhost:8001", # Assuming your frontend runs on 8001
    "http://127.0.0.1",
    "http://127.0.0.1:8001",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Load the trained Pipeline model ---
# The model is a Pipeline that includes TF-IDF and a classifier.
# It does NOT use a separate StandardScaler.
try:
    # Correct path and filename for your pipeline model
    model_pipeline = joblib.load('model/phishing_detector_model.joblib')
    print("Model pipeline loaded successfully.")
except FileNotFoundError:
    print("Error: Model pipeline file 'model/phishing_detector_model.joblib' not found.")
    print("Please ensure 'ml_model.py' has been run to train and save the model.")
    exit(1)
except Exception as e:
    print(f"Error loading model pipeline: {e}")
    exit(1)

class URLItem(BaseModel):
    url: str

# --- Feature Extraction Functions (REMOVE THESE - they are not used by your pipeline model) ---
# The pipeline handles feature extraction (TF-IDF) internally from the raw URL string.
# Keeping these here would be misleading and unused.
# If you wanted to add *additional* numerical features to your pipeline, you'd need
# to use a ColumnTransformer or similar sklearn utility in your ml_model.py.
# For now, we're sticking to the TF-IDF on raw URL.

# --- Main Feature Extraction Function (REMOVE THIS) ---
# This is no longer needed as the pipeline takes the raw URL.
# def extract_features(url):
#     ...

@app.post("/scan_url")
async def scan_url(item: URLItem):
    url = item.url.strip()

    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    # Basic URL validation (can be more robust)
    # This is for frontend feedback, not for the model itself
    if not re.match(r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', url):
        return {"status": "error", "message": "Invalid URL format. Please include http:// or https://"}

    try:
        # The model_pipeline expects the raw URL string directly
        # It handles TF-IDF transformation internally.
        
        # Make prediction
        # prediction will be an array, take the first element
        prediction = model_pipeline.predict([url])[0]
        # prediction_proba will be an array of probabilities for each class
        prediction_proba = model_pipeline.predict_proba([url])[0]

        status = "safe"
        confidence = prediction_proba[0] # Confidence for 'safe' (class 0)

        if prediction == 1: # Assuming 1 is malicious/phishing
            status = "dangerous"
            confidence = prediction_proba[1] # Confidence for 'dangerous' (class 1)
        
        # For simplicity, let's define suspicious as a range where confidence isn't very high for either
        # You might adjust these thresholds based on your model's performance
        if 0.4 < confidence < 0.6: # If confidence for either class is in this range
             status = "suspicious"

        # --- Detailed Features (Re-introduce the ones from ml_model.py if desired) ---
        # Since your ml_model.py uses TF-IDF, the "details" we can provide
        # are the raw features you defined in ml_model.py, but they are NOT
        # what the model directly used for classification.
        # If you want to show these, you need to call them here.
        # Let's include a few simple ones for demonstration.
        detailed_features = {
            'url_length': len(url),
            'has_ip_address': 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', urlparse(url).netloc) else 0,
            'has_at_symbol': 1 if "@" in url else 0,
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'uses_https': 1 if url.lower().startswith('https') else 0,
            'domain': urlparse(url).netloc,
            'path': urlparse(url).path,
            'query': urlparse(url).query,
        }


        return {
            "status": status,
            "confidence": float(confidence),
            "url": url,
            "details": detailed_features # Return these for the frontend
        }

    except Exception as e:
        print(f"Error during URL scanning: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error during scan: {e}")

# Root endpoint for basic check
@app.get("/")
async def read_root():
    return {"message": "URL Scanner Backend is running!"}