import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
import joblib
import os
import re
from urllib.parse import urlparse

# Define paths
DATA_PATH = os.path.join(os.path.dirname(__file__), 'data', 'phishing_site_urls.csv')
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model', 'phishing_detector_model.joblib')

# --- Feature Extraction Functions ---
# These functions are used during training and must be consistent with prediction.
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
    return 1 if "//" in url else 0 # More specifically, check if it's not part of https://

def count_dots(url):
    return url.count('.')

def count_hyphens(url):
    return url.count('-')

def count_subdomains(url):
    domain = get_domain(url)
    if domain:
        return len(domain.split('.')) - 1 # .com has 1, example.com has 2
    return 0

# --- Model Training & Loading ---
def train_and_save_model():
    print("Training model...")
    # Ensure model directory exists
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

    # Load data
    data = pd.read_csv(DATA_PATH)
    data.columns = ['URL', 'Label'] # Rename columns for clarity

    # Map labels to 0 and 1
    # 'good' -> 0, 'bad' -> 1
    data['Label'] = data['Label'].map({'good': 0, 'bad': 1})

    # We'll use TF-IDF for the URL text itself as a primary feature
    # This pipeline processes the raw URL strings.
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(max_features=5000, analyzer='char')), # Use character n-grams
        ('classifier', RandomForestClassifier(n_estimators=100, random_state=42))
    ])

    X = data['URL']
    y = data['Label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    pipeline.fit(X_train, y_train)

    # Evaluate (optional, but good practice)
    accuracy = pipeline.score(X_test, y_test)
    print(f"Model accuracy on test set: {accuracy:.2f}")

    # Save the trained pipeline
    joblib.dump(pipeline, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")
    return pipeline

def load_phishing_model():
    """
    Loads the pre-trained phishing detection model.
    If the model doesn't exist, it trains and saves a new one.
    """
    if not os.path.exists(MODEL_PATH):
        print("Model not found. Training and saving a new one...")
        return train_and_save_model()
    
    print("Loading pre-trained model...")
    return joblib.load(MODEL_PATH)

# No global model variable or initialize_model function here.
# The model will be loaded and returned by load_phishing_model()
# and then assigned to app.state in main.py.