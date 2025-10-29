# main.py

from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import joblib
import re
import numpy as np
from urllib.parse import urlparse
import tldextract # Import tldextract here
from urllib.parse import urlparse, parse_qs
import pandas as pd
from scipy.sparse import hstack
import csv
from datetime import datetime
from database import SessionLocal, engine, Base, Scan, Feedback, get_db
from sqlalchemy.orm import Session

# --- Tell SQLAlchemy to create the tables ---
# This will create the phisheye.db file and the tables
Base.metadata.create_all(bind=engine)


app = FastAPI()

# Configure CORS
origins = [
    "http://localhost",
    "http://localhost:8001",
    "http://127.0.0.1",
    "http://127.00.1:8001",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def load_tranco_list(csv_path="top-1m.csv"):
    """Loads the Tranco domain list from a CSV into a set for fast lookup."""
    print(f"Attempting to load Tranco whitelist from {csv_path}...")
    tranco_domains = set()

    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) == 2:
                    # The format is rank,domain
                    tranco_domains.add(row[1])

        if tranco_domains:
            print(f"Successfully loaded {len(tranco_domains)} domains into the whitelist.")
        else:
            print("WARNING: Tranco list was found but appears to be empty")
        return tranco_domains
    
    except FileNotFoundError:
        print(f"CRITICAL ERROR: '{csv_path}' not found.")
        print("Whitelist will be empty. Please download the file.")
        return set()
    
    except Exception as e:
        print(f"CRITICAL ERROR: Could not load Tranco List: {e}")
        return set()

MASTER_WHITELIST_SET = load_tranco_list()

# --- Load the trained Pipeline model ---
try:
    model_pipeline = joblib.load('model/phishing_detector_model.joblib') # Changed
    vectorizer = joblib.load('model/tfidf_vectorizer.joblib') # Changed
    print("Model pipeline and vectorizer loaded successfully.")
except FileNotFoundError:
    print("Error: Model or vectorizer file not found. Please ensure 'ml_model.py' has been run to train and save the model.")
    exit(1)
except Exception as e:
    print(f"Error loading model pipeline or vectorizer: {e}")
    exit(1)

class URLItem(BaseModel):
    url: str


# NEW: Pydantic model for receiving feedback
class FeedbackItem(BaseModel):
    scan_id: int
    report_type: str # 'false_positive' or 'false_negative'

# --- KNOWN LEGITIMATE DOMAINS LIST (Copied from ml_model.py) ---
KNOWN_LEGITIMATE_DOMAINS_LIST = [
    '1password.com', 'about.google', 'accuweather.com', 'adidas.com',
    'adobe.com', 'ai.google', 'airbnb.com', 'airtable.com',
    'akamai.com', 'alamy.com', 'allrecipes.com', 'amazon.com',
    'amd.com', 'americanexpress.com', 'analytics.ai', 'aol.com',
    'apnews.com', 'apple.com', 'asana.com', 'assets.net',
    'atlassian.com', 'atom.io', 'audi.com', 'australia.gov.au',
    'autodesk.com', 'badgen.net', 'banking.com', 'bankofamerica.com',
    'bbc.com', 'berkeley.edu', 'bestbuy.com', 'bing.com',
    'bitbucket.org', 'blender.org','blog.google', 'blogger.com',
    'bloomberg.com', 'bmw.com', 'booking.com', 'businessinsider.com',
    'calicocare.com', 'cam.ac.uk', 'canada.ca', 'canva.com',
    'capitalg.com', 'capitalone.com', 'cdc.gov', 'chase.com',
    'chevrolet.com', 'chronicle.security', 'citibank.com', 'cloudflare.com',
    'cloudservice.app', 'cnet.com', 'cnn.com', 'cocoapods.org',
    'community.org', 'company.info', 'confluence.com', 'costco.com',
    'coursera.org', 'craigslist.org', 'crates.io', 'customer.biz',
    'cvs.com', 'dailymotion.com', 'dashlane.com', 'deepmind.com',
    'dell.com', 'depositphotos.com', 'developer.tech', 'devicon.dev',
    'discord.com', 'discovery.com', 'domain.co.uk', 'dominos.com',
    'doordash.com', 'draw.io', 'dreamstime.com', 'dropbox.com',
    'drupal.org', 'duckduckgo.com', 'ebay.com', 'ecommerce.io',
    'education.edu', 'edx.org', 'epicurious.com', 'espn.com',
    'esri.com', 'etsy.com', 'europa.eu', 'evernote.com',
    'example.com', 'expedia.com', 'expressvpn.com', 'facebook.com',
    'fastly.com', 'figma.com', 'fitbit.com', 'flaticon.com',
    'flickr.com', 'fontawesome.com', 'foodnetwork.com', 'forbes.com',
    'ford.com', 'foxnews.com', 'freepik.com', 'freshdesk.com',
    'gamespot.com', 'gettyimages.com', 'gimp.org', 'github.com',
    'github.io', 'gitlab.com', 'gmail.com', 'godaddy.com',
    'google.com', 'gov.uk', 'grubhub.com', 'gv.com',
    'harvard.edu', 'health.google', 'healthline.com', 'heroicons.com',
    'hex.pm', 'history.com', 'hm.com', 'homedepot.com',
    'honda.com', 'hp.com', 'hubspot.com', 'huffpost.com',
    'ibm.com', 'icloud.com', 'iconfinder.com', 'ign.com',
    'imdb.com', 'imf.org', 'imgur.com', 'instacart.com',
    'instagram.com', 'intel.com', 'intrin.sic', 'intuit.com',
    'invisionapp.com', 'istockphoto.com', 'joomla.org', 'khanacademy.org',
    'lastpass.com', 'libraries.io', 'linkedin.com', 'live.com',
    'looker.com', 'loon.com', 'lowes.com', 'lucidchart.com',
    'lyft.com', 'mapbox.com', 'mastercard.com', 'materialui.com',
    'mayoclinic.org', 'mcdonalds.com', 'medium.com', 'mercedes-benz.com',
    'microsoft.com', 'miro.com', 'mit.edu', 'mobileapp.xyz',
    'monday.com', 'mozilla.org', 'msn.com', 'mysite.net',
    'namecheap.com', 'nasa.gov', 'nationalgeographic.com', 'nest.com',
    'netflix.com', 'nih.gov', 'nike.com', 'nordvpn.com',
    'notion.so', 'npr.org', 'nuget.org', 'nvidia.com',
    'nytimes.com', 'openstreetmap.org', 'opentable.com', 'oracle.com',
    'ox.ac.uk', 'packagist.org', 'pandora.com', 'paypal.com',
    'pbs.org', 'pexels.com', 'pinterest.com', 'pixabay.com', 
    'pizzahut.com', 'proton.me', 'protonmail.com', 'protonvpn.com',
    'python.org', 'qgis.org', 'quora.com', 'reddit.com',
    'reuters.com', 'rottentomatoes.com', 'rubygems.org', 'salesforce.com',
    'seriouseats.com', 'service.com', 'servicenow.com', 'shields.io',
    'shopify.com', 'shutterstock.com', 'sidewalklabs.com', 'simpleicons.org',
    'sketch.com', 'skillicons.dev', 'slack.com', 'smartsheet.com',
    'software.org', 'soundcloud.com', 'spacex.com', 'spotify.com',
    'square.com', 'squarespace.com', 'stackoverflow.com', 'stanford.edu',
    'starbucks.com', 'stripe.com', 'sustainability.google', 'tableau.com',
    'tabler-icons.io', 'target.com', 'techcrunch.com', 'tesla.com',
    'test.org', 'theguardian.com', 'thenounproject.com', 'theverge.com',
    'tiktok.com', 'toyota.com', 'travelchannel.com', 'trello.com', 
    'tripadvisor.com', 'tumblr.com', 'twitch.tv', 'twitter.com',
    'uber.com', 'udemy.com', 'un.org', 'unsplash.com',
    'usa.gov', 'usatoday.com', 'vectorstock.com', 'verily.com', 
    'vimeo.com', 'visa.com', 'visualstudio.com', 'w3schools.com',
    'walgreens.com', 'walmart.com', 'washingtonpost.com', 'waymo.com',
    'weather.com', 'webmd.com', 'website.com', 'wellsfargo.com',
    'who.int', 'wikipedia.org', 'wing.com', 'wired.com',
    'wix.com', 'wordpress.com', 'wordpress.org', 'worldbank.org',
    'wsj.com', 'x.company', 'yahoo.com', 'yelp.com',
    'youtube.com', 'zara.com', 'zendesk.com', 'zoom.us',

    # --- List of Popular Indian Domains to Add ---
    # E-commerce & Shopping
    'amazon.in',
    'flipkart.com',
    'myntra.com',
    'ajio.com',
    'nykaa.com',
    'jiomart.com',
    'snapdeal.com',
    'indiamart.com',

    # News & Media
    'indiatimes.com', # For Times of India
    'ndtv.com',
    'thehindu.com',
    'indianexpress.com',
    'indiatoday.in',
    'moneycontrol.com',
    'oneindia.com',

    # Services, Travel & Entertainment
    'zomato.com',
    'swiggy.com',
    'paytm.com',
    'phonepe.com',
    'makemytrip.com',
    'goibibo.com',
    'redbus.in',
    'bookmyshow.com',
    'hotstar.com',
    'jiocinema.com',
    'zee5.com',
    'gaana.com',

    # Job & Real Estate Portals
    'naukri.com',
    'linkedin.com', # Already there but good to ensure
    '99acres.com',
    'magicbricks.com',

    # Telecom Providers
    'jio.com',
    'airtel.in',
    'myvi.in', # For Vodafone Idea

    # --- Indian Government & Academic Domains ---
    
    # National Portals (.gov.in)
    'gov.in', # This will cover many, but specifics are better
    'india.gov.in',
    'mygov.in',
    'pmindia.gov.in',
    'uidai.gov.in',      # Aadhaar
    'passportindia.gov.in',
    'incometax.gov.in',
    'digilocker.gov.in',

    # Key Services (.co.in, .org.in)
    'irctc.co.in',       # Railways
    'rbi.org.in',        # Reserve Bank of India
    'isro.gov.in',       # ISRO
    
    # Ministries & Departments (.nic.in)
    'nic.in', # Covers many national informatics centre sites
    'mohfw.gov.in',      # Ministry of Health
    'education.gov.in',  # Ministry of Education
    'meity.gov.in',      # Ministry of IT
    'morth.nic.in',      # Ministry of Road Transport
    'parivahan.gov.in',  # Transport Services

    # Academic & Research (.ac.in, .res.in)
    'ac.in', # Base for many academic institutions
    'nta.ac.in',         # National Testing Agency
    'ugc.ac.in',         # University Grants Commission
    'iitb.ac.in',        # IIT Bombay (example)
    'iitd.ac.in',        # IIT Delhi (example)
]

# --- Feature Extraction Function (Copied from ml_model.py) ---
# You need this function in main.py because the model expects these features
# alongside the TF-IDF features.
def extract_highly_discriminative_features(url):
    """
    Extracts a comprehensive set of highly discriminative features from a URL.
    Focuses on known phishing indicators and structural anomalies.
    Returns a list of numerical features.
    """
    features = []
    parsed_url = urlparse(url)
    ext = tldextract.extract(url, update=False) # Extracts subdomain, domain, suffix

    # 1. URL Length
    features.append(len(url))

    # 2. Number of dots in the hostname (more dots can indicate subdomains used for trickery)
    features.append(parsed_url.hostname.count('.') if parsed_url.hostname else 0)

    # 3. Presence of 'https' (1 if present, 0 otherwise)
    features.append(1 if parsed_url.scheme == 'https' else 0)

    # 4. Presence of common phishing keywords in the entire URL
    phishing_keywords = ['login', 'signin', 'verify', 'webscr', 'confirm', 'billing', 'admin', 'panel', 'cpanel', 'wp-admin', 'portal', 'client', 'myaccount', 'credential', 'authorize', 'suspicious', 'alert', 'compromised', 'deactivated', 'restricted', 'urgent', 'action', 'security', 'update']
    features.append(1 if any(keyword in url.lower() for keyword in phishing_keywords) else 0)

    # 5. Presence of '@' symbol in the URL (often used to embed credentials or trick users)
    features.append(1 if '@' in url else 0)

    # 6. Presence of IP address instead of domain name (e.g., http://192.168.1.1/login)
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    features.append(1 if parsed_url.hostname and re.match(ip_pattern, parsed_url.hostname) else 0)

    # 7. Shortening service (e.g., bit.ly, tinyurl - often used by phishers)
    shortening_services = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'cli.gs', 'buff.ly', 'rebrand.ly', 'cutt.ly']
    features.append(1 if any(service in parsed_url.netloc.lower() for service in shortening_services) else 0)

    # 8. Number of hyphens in the domain (excessive hyphens can be a sign of generated domains)
    features.append(ext.domain.count('-'))

    # 9. Length of hostname (very short or very long can be suspicious)
    features.append(len(parsed_url.hostname) if parsed_url.hostname else 0)

    # 10. Number of subdomains (e.g., www.sub.domain.com -> 2 subdomains)
    features.append(len(ext.subdomain.split('.')) if ext.subdomain else 0)

    # 11. Presence of query parameters (e.g., ?id=123, ?redirect=...)
    features.append(1 if parsed_url.query else 0)

    # 12. Length of query string
    features.append(len(parsed_url.query))

    # 13. Presence of fragment (#section)
    features.append(1 if parsed_url.fragment else 0)

    # 14. Port number in URL (uncommon for legitimate sites, e.g., :8080)
    features.append(1 if parsed_url.port else 0)

    # 15. Suspicious TLDs (Top-Level Domains) - expanded list
    suspicious_tlds = ['.zip', '.xyz', '.info', '.top', '.club', '.online', '.site', '.ru', '.cn', '.pw', '.ga', '.cf', '.tk', '.ml', '.gq', '.bid', '.loan', '.win', '.party', '.review', '.download', '.men', '.kim', '.science', '.date', '.link', '.click']
    features.append(1 if ext.suffix and any(tld == '.' + ext.suffix.lower() for tld in suspicious_tlds) else 0)

    # 16. Path depth (number of directories)
    features.append(parsed_url.path.count('/'))

    # 17. Presence of non-ASCII characters (punycode, often used in homograph attacks)
    features.append(1 if any(ord(c) > 127 for c in url) else 0)

    # 18. "Brand" impersonation in subdomain or path (e.g., microsoft.com.malicious.xyz)
    common_brands = ['google', 'microsoft', 'apple', 'amazon', 'paypal', 'ebay', 'facebook', 'instagram', 'netflix', 'bank']
    brand_impersonation_score = 0
    if ext.domain and ext.domain.lower() not in common_brands:
        for brand in common_brands:
            if brand in url.lower() and brand not in ext.domain.lower():
                brand_impersonation_score = 1
                break
    features.append(brand_impersonation_score)

    # 19. Redirects in query parameters (e.g., ?redirect=http://malicious.com)
    query_params = parse_qs(parsed_url.query)
    redirect_keywords = ['redirect', 'url', 'return', 'next', 'continue', 'destination']
    redirect_found = 0
    for key, values in query_params.items():
        if any(rk in key.lower() for rk in redirect_keywords):
            for value in values:
                if 'http' in value.lower() or 'https' in value.lower():
                    redirect_found = 1
                    break
        if redirect_found:
            break
    features.append(redirect_found)

    # 20. Is it a known legitimate domain? (STRONG SIGNAL)
    features.append(1 if ext.top_domain_under_public_suffix and ext.top_domain_under_public_suffix.lower() in KNOWN_LEGITIMATE_DOMAINS_LIST else 0)

    # 21. Has common legitimate path/query keywords (to counteract phishing keywords)
    legitimate_path_keywords = ['order', 'history', 'account', 'profile', 'settings', 'dashboard', 'summary', 'cart', 'checkout', 'product', 'category', 'item', 'view', 'manage', 'details', 'status', 'help', 'support', 'contact', 'about', 'privacy', 'terms']
    features.append(1 if any(keyword in url.lower() for keyword in legitimate_path_keywords) else 0)

    return features


@app.post("/scan_url")
async def scan_url(item: URLItem, db: Session = Depends(get_db)): # <-- 1. ADDED database session
    url = item.url.strip()

    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    # Basic URL validation (can be more robust)
    if not re.match(r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', url):
        return {"status": "error", "message": "Invalid URL format. Please include http:// or https://"}

    try:
        # --- 2. Initialize variables to store results ---
        scan_status = ""
        scan_confidence = 0.0
        scan_whitelisted = False
        scan_features = {} # To store the detailed features

        # --- RULE-BASED WHITELIST OVERRIDE ---
        ext = tldextract.extract(url, update=False)
        if ext.top_domain_under_public_suffix and ext.top_domain_under_public_suffix.lower() in MASTER_WHITELIST_SET:
            
            # --- 3. SET variables instead of returning ---
            scan_status = "safe"
            scan_confidence = 0.999
            scan_whitelisted = True
            scan_features = {
                'reason': 'Whitelisted Domain',
                'domain': ext.top_domain_under_public_suffix,
                'url_length': len(url),
                'uses_https': 1 if url.lower().startswith('https') else 0,
            }
        
        else:
            # --- 4. This is the ML model path ---
            scan_whitelisted = False
            
            # Extract TF-IDF features
            url_tfidf = vectorizer.transform([url]) # Use the loaded vectorizer

            # Extract additional numerical features
            url_additional = pd.DataFrame([extract_highly_discriminative_features(url)])

            # Combine features
            from scipy.sparse import hstack # Import hstack here if not already at top
            url_combined = hstack([url_tfidf, url_additional])
            
            # Make prediction
            prediction = model_pipeline.predict(url_combined)[0]
            prediction_proba = model_pipeline.predict_proba(url_combined)[0]

            # --- 5. SET variables for ML result ---
            if prediction == 1: # Assuming 1 is malicious/phishing
                scan_status = "dangerous"
                scan_confidence = prediction_proba[1] # Confidence for 'dangerous' (class 1)
            else:
                scan_status = "safe"
                scan_confidence = prediction_proba[0] # Confidence for 'safe' (class 0)
            
            if 0.4 < scan_confidence < 0.6: 
                 scan_status = "suspicious"

            # --- Detailed Features ---
            scan_features = {
                'url_length': len(url),
                'has_ip_address': 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', urlparse(url).netloc) else 0,
                'has_at_symbol': 1 if "@" in url else 0,
                'num_dots': url.count('.'),
                'num_hyphens': url.count('-'),
                'uses_https': 1 if url.lower().startswith('https') else 0,
                'domain': urlparse(url).netloc,
                'path': urlparse(url).path,
                'query': urlparse(url).query,
                'has_phishing_keywords': extract_highly_discriminative_features(url)[3],
                'is_shortened': extract_highly_discriminative_features(url)[6],
                'num_subdomains': extract_highly_discriminative_features(url)[9],
                'suspicious_tld': extract_highly_discriminative_features(url)[14],
                'is_known_legit_domain_feature': extract_highly_discriminative_features(url)[19]
            }

        # --- 6. DATABASE LOGGING (FEATURE 1) ---
        # This part runs AFTER the if/else block, so it logs ALL scans
        new_scan = Scan(
            url=url,
            status=scan_status,
            confidence=float(scan_confidence),
            was_whitelisted=scan_whitelisted,
            timestamp=datetime.utcnow()
        )
        db.add(new_scan)
        db.commit()
        db.refresh(new_scan) # Get the new_scan.id back
        # --- End of Logging ---

        # --- 7. FINAL RETURN ---
        # Now we return the data, including the new scan_id
        return {
            "scan_id": new_scan.id, # <-- ADDED
            "status": scan_status,
            "confidence": float(scan_confidence),
            "url": url,
            "detailed_features": scan_features
        }

    except Exception as e:
        print(f"Error during URL scanning: {e}")
        db.rollback() # <-- 8. ADDED rollback on error
        raise HTTPException(status_code=500, detail=f"Internal server error during scan: {e}")
    
# --- New ENDPOINT for feedback (featur 1) ---
@app.post("/report_feedback")
async def report_feedback(item: FeedbackItem, db: Session = Depends(get_db)):
    """Endpoint for users to report an incorrect prediction"""
    # 1. Check if the original scan exists
    scan = db.query(Scan).filter(Scan.id == item.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Original scan not found.")
    
    # 2. Check if feedback for this scan already exists
    existing_feedback = db.query(Feedback).filter(Feedback.scan_id == item.scan_id).first()
    if existing_feedback:
        return {"message": "Feedback for this scan has already been recorded."}
    
    # 3. Save the new feedback
    new_feedback = Feedback(
        scan_id=item.scan_id,
        report_type=item.report_type,
        timestamp=datetime.utcnow()
    )
    db.add(new_feedback)
    db.commit()

    print(f"Feedback received for the scan {item.scan_id}: {item.report_type}")

    # main.py
from fastapi import FastAPI, HTTPException, Depends  # <-- Add Depends
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import joblib
# ... (all your other imports) ...
from datetime import datetime  # <-- Add datetime

# --- Import from your new database.py file ---
from database import SessionLocal, engine, Base, Scan, Feedback, get_db
from sqlalchemy.orm import Session # <-- Add Session

# --- Tell SQLAlchemy to create the tables ---
# This will create the 'phisheye.db' file and the tables
Base.metadata.create_all(bind=engine)


app = FastAPI()

# ... (Your CORS middleware setup) ...
# ... (Your load_tranco_list function) ...
# ... (Your model/vectorizer loading) ...

class URLItem(BaseModel):
    url: str

# NEW: Pydantic model for receiving feedback
class FeedbackItem(BaseModel):
    scan_id: int
    report_type: str # 'false_positive' or 'false_negative'


# --- Modify your /scan_url endpoint ---
@app.post("/scan_url")
async def scan_url(item: URLItem, db: Session = Depends(get_db)): # <-- Add db session
    url = item.url.strip()

    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
    
    # ... (Your basic URL validation) ...

    # We will add Caching (Feature 2) logic here later.
    # For now, we just scan and log.

    try:
        scan_status = ""
        scan_confidence = 0.0
        scan_whitelisted = False
        scan_features = {} # To store the detailed features

        # --- RULE-BASED WHITELIST OVERRIDE ---
        ext = tldextract.extract(url)
        if ext.top_domain_under_public_suffix and ext.top_domain_under_public_suffix.lower() in MASTER_WHITELIST_SET:
            scan_status = "safe"
            scan_confidence = 0.999
            scan_whitelisted = True
            scan_features = {
                'reason': 'Whitelisted Domain',
                'domain': ext.top_domain_under_public_suffix,
            }

        else:
            # --- ML Model Prediction ---
            scan_whitelisted = False
            
            # (Your feature extraction and prediction logic)
            url_tfidf = vectorizer.transform([url])
            url_additional = pd.DataFrame([extract_highly_discriminative_features(url)])
            url_combined = hstack([url_tfidf, url_additional])
            
            prediction = model_pipeline.predict(url_combined)[0]
            prediction_proba = model_pipeline.predict_proba(url_combined)[0]
            
            if prediction == 1: # Assuming 1 is malicious
                scan_status = "dangerous"
                scan_confidence = prediction_proba[1]
            else:
                scan_status = "safe"
                scan_confidence = prediction_proba[0]

            if 0.4 < scan_confidence < 0.6:
                 scan_status = "suspicious"
            
            # (Your detailed_features dictionary creation)
            scan_features = {
                'url_length': len(url),
                # ... (all your other features) ...
            }

        # --- 🚀 DATABASE LOGGING (FEATURE 1) ---
        new_scan = Scan(
            url=url,
            status=scan_status,
            confidence=float(scan_confidence),
            was_whitelisted=scan_whitelisted,
            timestamp=datetime.utcnow()
        )
        db.add(new_scan)
        db.commit()
        db.refresh(new_scan) # Get the new_scan.id back
        # --- End of Logging ---

        return {
            "scan_id": new_scan.id, # <-- SEND THE NEW ID TO THE FRONTEND
            "status": scan_status,
            "confidence": float(scan_confidence),
            "url": url,
            "detailed_features": scan_features
        }

    except Exception as e:
        print(f"Error during URL scanning: {e}")
        db.rollback() # Rollback any db changes on error
        raise HTTPException(status_code=500, detail=f"Internal server error during scan: {e}")


# --- 🚀 NEW ENDPOINT FOR FEEDBACK (FEATURE 1) ---
@app.post("/report_feedback")
async def report_feedback(item: FeedbackItem, db: Session = Depends(get_db)):
    """
    Endpoint for users to report an incorrect prediction.
    """
    
    # 1. Check if the original scan exists
    scan = db.query(Scan).filter(Scan.id == item.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Original scan not found.")
        
    # 2. Check if feedback for this scan already exists
    existing_feedback = db.query(Feedback).filter(Feedback.scan_id == item.scan_id).first()
    if existing_feedback:
        return {"message": "Feedback for this scan has already been recorded."}
        
    # 3. Save the new feedback
    new_feedback = Feedback(
        scan_id=item.scan_id,
        report_type=item.report_type,
        timestamp=datetime.utcnow()
    )
    db.add(new_feedback)
    db.commit()
    
    print(f"Feedback received for scan {item.scan_id}: {item.report_type}")
    
    return {
        "message": "Feedback successfully recorded.",
        "scan_id": item.scan_id,
        "reported_as": item.report_type
    }

# Root endpoint for basic check
@app.get("/")
async def read_root():
    return {"message": "URL Scanner Backend is running!"}