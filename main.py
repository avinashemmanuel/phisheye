# main.py

from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import joblib
import re
import numpy as np
from urllib.parse import urlparse, parse_qs
import pandas as pd
from scipy.sparse import hstack
import csv
from datetime import datetime, timedelta
from typing import Union # For Python 3.9 compatibility
import tldextract
from starlette.concurrency import run_in_threadpool # <-- IMPORT THIS
from scipy.sparse import hstack, csr_matrix

# --- Database Imports ---
from database import SessionLocal, engine, Base, Scan, Feedback, User, get_db
from sqlalchemy.orm import Session

# --- Auth Imports ---
from auth import (
    hash_password,
    verify_password,
    create_api_key,
    get_current_user
)

# --- Tell SQLAlchemy to create the tables ---
Base.metadata.create_all(bind=engine)


app = FastAPI()

# --- Configure CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow all for local dev
    allow_credentials=False,
    allow_methods=["POST", "OPTIONS", "GET"], # <-- ADDED GET
    allow_headers=["*"],
)

# --- Whitelist Loading ---
def load_tranco_list(csv_path="top-1m.csv"):
    """Loads the Tranco domain list from a CSV into a set for fast lookup."""
    print(f"Attempting to load Tranco whitelist from {csv_path}...")
    tranco_domains = set()
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) == 2:
                    tranco_domains.add(row[1])
        print(f"Successfully loaded {len(tranco_domains)} domains into the whitelist.")
        return tranco_domains
    except FileNotFoundError:
        print(f"CRITICAL ERROR: '{csv_path}' not found.")
        return set()
    except Exception as e:
        print(f"CRITICAL ERROR: Could not load Tranco List: {e}")
        return set()

MASTER_WHITELIST_SET = load_tranco_list()

# --- Load ML Model ---
try:
    model_pipeline = joblib.load('model/phishing_detector_model.joblib')
    vectorizer = joblib.load('model/tfidf_vectorizer.joblib')
    print("Model pipeline and vectorizer loaded successfully.")
except Exception as e:
    print(f"Error loading model pipeline or vectorizer: {e}")
    exit(1)

# --- Pydantic Models ---
class URLItem(BaseModel):
    url: str

class FeedbackItem(BaseModel):
    scan_id: int
    report_type: str # 'false_positive' or 'false_negative'

class UserCreate(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    email: str
    api_key: str

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

# --- Feature Extraction Function ---
# THIS IS NOW AN ASYNC FUNCTION
async def extract_highly_discriminative_features(url):
    """
    Extracts a comprehensive set of highly discriminative features from a URL.
    Runs tldextract in a threadpool to avoid blocking.
    """
    features = []
    parsed_url = urlparse(url)
    
    # --- RUN BLOCKING I/O IN THREADPOOL ---
    try:
        # This runs tldextract in a separate thread
        ext = await run_in_threadpool(tldextract.extract, url)
    except Exception as e:
        print(f"TLDExtract failed for url {url}: {e}")
        # Create a dummy object so the rest of the code doesn't fail
        class DummyExt:
            domain = ""
            suffix = ""
            subdomain = ""
            top_domain_under_public_suffix = "" # Use property
                
        ext = DummyExt()
    # --- END OF THREADPOOL ---

    # 1. URL Length
    features.append(len(url))
    # 2. Number of dots
    features.append(parsed_url.hostname.count('.') if parsed_url.hostname else 0)
    # 3. Presence of 'https'
    features.append(1 if parsed_url.scheme == 'https' else 0)
    # 4. Phishing keywords
    phishing_keywords = ['login', 'signin', 'verify', 'webscr', 'confirm', 'billing', 'admin', 'panel', 'credential', 'security', 'update']
    features.append(1 if any(keyword in url.lower() for keyword in phishing_keywords) else 0)
    # 5. Presence of '@'
    features.append(1 if '@' in url else 0)
    # 6. IP address in hostname
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    features.append(1 if parsed_url.hostname and re.match(ip_pattern, parsed_url.hostname) else 0)
    # 7. Shortening service
    shortening_services = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']
    features.append(1 if any(service in parsed_url.netloc.lower() for service in shortening_services) else 0)
    # 8. Number of hyphens in domain
    features.append(ext.domain.count('-'))
    # 9. Length of hostname
    features.append(len(parsed_url.hostname) if parsed_url.hostname else 0)
    # 10. Number of subdomains
    features.append(len(ext.subdomain.split('.')) if ext.subdomain else 0)
    # 11. Query parameters
    features.append(1 if parsed_url.query else 0)
    # 12. Length of query
    features.append(len(parsed_url.query))
    # 13. Presence of fragment
    features.append(1 if parsed_url.fragment else 0)
    # 14. Port number
    features.append(1 if parsed_url.port else 0)
    # 15. Suspicious TLDs
    suspicious_tlds = ['.zip', '.xyz', '.info', '.top', '.club', '.online', '.site', '.ru', '.cn', '.pw', '.link', '.click']
    features.append(1 if ext.suffix and any(tld == '.' + ext.suffix.lower() for tld in suspicious_tlds) else 0)
    # 16. Path depth
    features.append(parsed_url.path.count('/'))
    # 17. Non-ASCII chars
    features.append(1 if any(ord(c) > 127 for c in url) else 0)
    # 18. Brand impersonation
    common_brands = ['google', 'microsoft', 'apple', 'amazon', 'paypal', 'ebay', 'facebook', 'instagram', 'netflix', 'bank']
    brand_impersonation_score = 0
    if ext.domain and ext.domain.lower() not in common_brands:
        for brand in common_brands:
            if brand in url.lower() and brand not in ext.domain.lower():
                brand_impersonation_score = 1
                break
    features.append(brand_impersonation_score)
    # 19. Redirects in query
    query_params = parse_qs(parsed_url.query)
    redirect_keywords = ['redirect', 'url', 'return', 'next']
    redirect_found = 0
    for key, values in query_params.items():
        if any(rk in key.lower() for rk in redirect_keywords):
            for value in values:
                if 'http' in value.lower():
                    redirect_found = 1
                    break
        if redirect_found:
            break
    features.append(redirect_found)
    
    # 20. Is known legit domain (ML feature)
    tld_main_domain = ext.top_domain_under_public_suffix
    features.append(1 if tld_main_domain and tld_main_domain.lower() in KNOWN_LEGITIMATE_DOMAINS_LIST else 0)
    
    # 21. Legitimate path keywords
    legitimate_path_keywords = ['order', 'history', 'account', 'profile', 'settings', 'dashboard', 'cart', 'help', 'contact', 'about']
    features.append(1 if any(keyword in url.lower() for keyword in legitimate_path_keywords) else 0)

    return features

# --- API Endpoints ---

@app.post("/scan_url")
async def scan_url(
    item: URLItem, 
    db: Session = Depends(get_db),
    current_user: Union[User, None] = Depends(get_current_user)
):
    url = item.url.strip()

    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
    if not re.match(r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', url):
        return {"status": "error", "message": "Invalid URL format. Please include http:// or https://"}

    user_id = current_user.id if current_user else None

    try:
        # --- CACHING LOGIC (FEATURE 2) ---
        cache_duration = timedelta(hours=6)
        cache_expiry_time = datetime.utcnow() - cache_duration

        cached_scan = db.query(Scan).filter(
            Scan.url == url,
            Scan.timestamp >= cache_expiry_time
        ).order_by(Scan.timestamp.desc()).first()

        if cached_scan:
            print(f"CACHE HIT: Returning saved result for {url}")
            if current_user is None:
                return {"scan_id": cached_scan.id, "status": cached_scan.status}
            else:
                # Run in threadpool to avoid blocking
                cached_domain_ext = await run_in_threadpool(tldextract.extract, url)
                cached_features = {
                    'reason': 'Cached Result',
                    'domain': cached_domain_ext.top_domain_under_public_suffix,
                    'was_whitelisted': cached_scan.was_whitelisted
                }
                return {
                    "scan_id": cached_scan.id,
                    "status": cached_scan.status,
                    "confidence": float(cached_scan.confidence),
                    "url": cached_scan.url,
                    "detailed_features": cached_features
                }
        
        print(f"CACHE MISS: Performing new scan for {url}")
        
        # --- SCAN LOGIC ---
        scan_status = ""
        scan_confidence = 0.0
        scan_whitelisted = False
        scan_features = {} 

        # --- RUN BLOCKING I/O IN THREADPOOL ---
        ext = await run_in_threadpool(tldextract.extract, url)
        # ---
        
        tld_main_domain = ext.top_domain_under_public_suffix

        if tld_main_domain and tld_main_domain.lower() in MASTER_WHITELIST_SET:
            scan_status = "safe"
            scan_confidence = 0.999
            scan_whitelisted = True
            scan_features = {
                'reason': 'Whitelisted Domain',
                'domain': tld_main_domain,
            }
        
        else:
            scan_whitelisted = False
            
            # --- RUN BLOCKING I/O IN THREADPOOL ---
            # The ML model's `predict` is CPU-bound, so run_in_threadpool
            # is the right way to avoid blocking the async loop.
            
            # 1. Get features (which is now async)
            features_list = await extract_highly_discriminative_features(url)
            
            # 2. Transform (this is fast, no thread needed)
            url_tfidf = vectorizer.transform([url])
            url_additional = pd.DataFrame([features_list])
            url_additional_csr = csr_matrix(url_additional.values)
            url_combined = hstack([url_tfidf, url_additional])
            
            # 3. Predict (this is slow, run in thread)
            def predict_in_thread():
                prediction = model_pipeline.predict(url_combined)[0]
                prediction_proba = model_pipeline.predict_proba(url_combined)[0]
                return prediction, prediction_proba

            prediction, prediction_proba = await run_in_threadpool(predict_in_thread)
            # --- END OF THREADPOOL ---

            if prediction == 1:
                scan_status = "dangerous"
                scan_confidence = prediction_proba[1]
            else:
                scan_status = "safe"
                scan_confidence = prediction_proba[0]
            
            if 0.4 < scan_confidence < 0.6: 
                 scan_status = "suspicious"

            # We can re-use features_list to build scan_features
            # Need to re-parse the URL here as we don't have parsed_url from the async func
            parsed_url = urlparse(url) 
            scan_features = {
                'url_length': features_list[0],
                'has_ip_address': features_list[5],
                'has_at_symbol': features_list[4],
                'num_dots': features_list[1],
                'num_hyphens': features_list[7],
                'uses_https': features_list[2],
                'domain': parsed_url.netloc,
                'path': parsed_url.path,
                'query': parsed_url.query,
                'has_phishing_keywords': features_list[3],
                'is_shortened': features_list[6],
                'num_subdomains': features_list[9],
                'suspicious_tld': features_list[14],
                'is_known_legit_domain_feature': features_list[19]
            }

        # --- DATABASE LOGGING ---
        new_scan = Scan(
            url=url,
            status=scan_status,
            confidence=float(scan_confidence),
            was_whitelisted=scan_whitelisted,
            timestamp=datetime.utcnow(),
            user_id=user_id
        )
        db.add(new_scan)
        db.commit()
        db.refresh(new_scan)

        # --- TIERED RETURN ---
        if current_user is None:
            return {"scan_id": new_scan.id, "status": scan_status}
        else:
            return {
                "scan_id": new_scan.id,
                "status": scan_status,
                "confidence": float(scan_confidence),
                "url": url,
                "detailed_features": scan_features
            }

    except Exception as e:
        print(f"Error during URL scanning: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Internal server error during scan: {e}")

# --- USER AUTH ENDPOINTS ---

@app.post("/register", response_model=UserResponse)
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    pw_bytes = user.password.encode("utf-8")
    if len(pw_bytes) > 72:
        raise HTTPException(status_code=400, detail="Password too long (max. 72 bytes). Please use a shorter password.")
    hashed_pass = hash_password(user.password)
    new_api_key = create_api_key()
    
    new_user = User(
        email=user.email,
        hashed_password=hashed_pass,
        api_key=new_api_key
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {"email": new_user.email, "api_key": new_user.api_key}

@app.post("/login", response_model=UserResponse)
async def login_user(form_data: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == form_data.email).first()
    
    if not db_user or not verify_password(form_data.password, db_user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password"
        )
    
    return {"email": db_user.email, "api_key": db_user.api_key}

@app.post("/report_feedback")
async def report_feedback(
    item: FeedbackItem, 
    db: Session = Depends(get_db),
    current_user: Union[User, None] = Depends(get_current_user)
):
    if current_user is None:
         raise HTTPException(status_code=401, detail="You must be logged in to report feedback.")

    scan = db.query(Scan).filter(Scan.id == item.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Original scan not found.")
        
    existing_feedback = db.query(Feedback).filter(
        Feedback.scan_id == item.scan_id,
        Feedback.user_id == current_user.id
    ).first()
    
    if existing_feedback:
        return {"message": "You have already reported feedback for this scan."}
        
    new_feedback = Feedback(
        scan_id=item.scan_id,
        report_type=item.report_type,
        timestamp=datetime.utcnow(),
        user_id=current_user.id
    )
    db.add(new_feedback)
    db.commit()
    
    print(f"Feedback received for scan {item.scan_id} from user {current_user.email}")
    
    return {
        "message": "Feedback successfully recorded.",
        "scan_id": item.scan_id,
        "reported_as": item.report_type
    }

# --- ROOT ENDPOINT ---
@app.get("/")
async def read_root():
    return {"message": "PhishEye Scanner Backend is running!"}