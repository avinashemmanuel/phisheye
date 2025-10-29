import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import re
from sklearn.utils import resample
from scipy.sparse import hstack
from urllib.parse import urlparse, parse_qs
import tldextract

# --- Configuration ---
DATA_PATH = 'data/final_url_dataset.csv'
MODEL_PATH = 'model/phishing_detector_model.joblib' # Changed
VECTORIZER_PATH = 'model/tfidf_vectorizer.joblib' # Changed

# Define known legitimate domains globally for easy access in predict_url
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


# --- Feature Engineering Function ---
def extract_highly_discriminative_features(url):
    """
    Extracts a comprehensive set of highly discriminative features from a URL.
    Focuses on known phishing indicators and structural anomalies.
    Returns a list of numerical features.
    """
    features = []
    parsed_url = urlparse(url)
    ext = tldextract.extract(url) # Extracts subdomain, domain, suffix

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
    # This feature is still used for training, but we'll add an explicit check in predict_url
    features.append(1 if ext.top_domain_under_public_suffix and ext.top_domain_under_public_suffix.lower() in KNOWN_LEGITIMATE_DOMAINS_LIST else 0)

    # 21. Has common legitimate path/query keywords (to counteract phishing keywords)
    legitimate_path_keywords = ['order', 'history', 'account', 'profile', 'settings', 'dashboard', 'summary', 'cart', 'checkout', 'product', 'category', 'item', 'view', 'manage', 'details', 'status', 'help', 'support', 'contact', 'about', 'privacy', 'terms']
    features.append(1 if any(keyword in url.lower() for keyword in legitimate_path_keywords) else 0)

    return features

# --- Training and Saving Model ---
def train_and_save_model():
    print(f"Loading dataset from {DATA_PATH}...")
    try:
        df = pd.read_csv(DATA_PATH)
    except FileNotFoundError:
        print(f"Error: Dataset not found at {DATA_PATH}. Please ensure the file exists.")
        return

    # --- Data Cleaning and Preparation ---
    if 'url' in df.columns:
        url_column = 'url'
    elif 'URL' in df.columns:
        url_column = 'URL'
    else:
        print("Error: Dataset must contain either a 'url' or 'URL' column.")
        print(f"Available columns: {df.columns.tolist()}")
        return

    if 'label' in df.columns:
        label_column = 'label'
    elif 'Label' in df.columns:
        label_column = 'Label'
    else:
        print("Error: Dataset must contain either a 'label' or 'Label' column.")
        print(f"Available columns: {df.columns.tolist()}")
        return

    initial_rows = len(df)
    df.dropna(subset=[url_column, label_column], inplace=True)
    rows_after_drop = len(df)
    if initial_rows > rows_after_drop:
        print(f"Dropped {initial_rows - rows_after_drop} rows with missing '{url_column}' or '{label_column}' values.")

    df[url_column] = df[url_column].astype(str)

    X = df[url_column]
    y = df[label_column]

    if len(X) == 0:
        print("Error: No data remaining after dropping rows with missing values. Cannot train model.")
        return

    print(f"Total samples after cleaning: {len(X)}")

    # --- Split data FIRST, then apply oversampling to training set ---
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # --- Apply Oversampling ONLY to the training data ---
    print("Checking for data imbalance in training set and performing oversampling if necessary...")
    df_train = pd.DataFrame({url_column: X_train, label_column: y_train})

    df_majority_train = df_train[df_train[label_column] == 0]
    df_minority_train = df_train[df_train[label_column] == 1]

    if len(df_minority_train) > 0 and len(df_majority_train) > len(df_minority_train) * 2:
        df_minority_upsampled = resample(df_minority_train,
                                         replace=True,
                                         n_samples=len(df_majority_train),
                                         random_state=42)

        df_balanced_train = pd.concat([df_majority_train, df_minority_upsampled])
        print(f"Oversampled minority class (Phishing) in training set from {len(df_minority_train)} to {len(df_balanced_train) - len(df_majority_train)} samples.")

        X_train = df_balanced_train[url_column]
        y_train = df_balanced_train[label_column]
    else:
        print("No significant imbalance detected in training set or oversampling not applied.")

    print(f"Total training samples after balancing: {len(X_train)}")


    # --- Feature Extraction and Combination ---
    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5), max_features=5000)
    print("Fitting TF-IDF Vectorizer...")
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)

    print("Extracting highly discriminative features...")
    X_train_additional = pd.DataFrame([extract_highly_discriminative_features(url) for url in X_train])
    X_test_additional = pd.DataFrame([extract_highly_discriminative_features(url) for url in X_test])

    X_train_combined = hstack([X_train_tfidf, X_train_additional])
    X_test_combined = hstack([X_test_tfidf, X_test_additional])


    # --- Train RandomForestClassifier Model ---
    print("Training RandomForestClassifier model...")
    model = RandomForestClassifier(n_estimators=500, random_state=42, class_weight='balanced',
                                   min_samples_leaf=20, max_depth=30,
                                   max_features='sqrt',
                                   min_samples_split=15)
    model.fit(X_train_combined, y_train)

    # Evaluate Model
    y_pred = model.predict(X_test_combined)
    print("\nModel Evaluation:")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("Classification Report:\n", classification_report(y_test, y_pred))

    # Save the trained model and vectorizer
    print(f"Saving model to {MODEL_PATH}...")
    joblib.dump(model, MODEL_PATH)
    print(f"Saving vectorizer to {VECTORIZER_PATH}...")
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print("Model and vectorizer saved successfully.")

# --- Prediction Function for a Single URL ---
def predict_url(url):
    # --- Rule-based override for known legitimate domains ---
    ext = tldextract.extract(url)
    if ext.top_domain_under_public_suffix and ext.top_domain_under_public_suffix.lower() in KNOWN_LEGITIMATE_DOMAINS_LIST:
        return 0 # Explicitly classify as Legitimate

    # If not a known legitimate domain, proceed with the ML model
    try:
        model = joblib.load(MODEL_PATH)
        vectorizer = joblib.load(VECTORIZER_PATH)
    except FileNotFoundError:
        print("Error: Model or vectorizer not found. Please train the model first.")
        return None

    # Preprocess the single URL
    url_tfidf = vectorizer.transform([url])
    url_additional = pd.DataFrame([extract_highly_discriminative_features(url)])
    url_combined = hstack([url_tfidf, url_additional])

    # Make prediction
    prediction = model.predict(url_combined)
    return prediction[0]

# --- Main Execution Block ---
if __name__ == "__main__":
    train_and_save_model()

    print("\n--- Testing single URL prediction ---")
    test_urls = [
        "https://www.google.com",
        "https://en.wikipedia.org/wiki/Main_Page",
        "http://phishing-site.com/login.html",
        "https://secure-bank-update.net/verify.php?id=12345",
        "http://example.com/safe-page",
        "http://bank.com.phishing.ru/login.php",
        "https://www.microsoft.com/en-us/windows",
        "http://login.microsoft.com.malicious.xyz/signin.php",
        "https://www.amazon.com/gp/css/order-history?ref_=nav_orders_first", # Should be Legitimate (0)
        "http://amazon.security-update.co/login.php?id=user123", # Should be Phishing (1)
        "https://www.paypal.com/myaccount/summary", # Another legitimate
        "http://paypal.com.login-secure.xyz/update.php" # Another phishing
    ]

    for url in test_urls:
        prediction = predict_url(url)
        if prediction is not None:
            status = "Phishing" if prediction == 1 else "Legitimate"
            print(f"URL: {url} -> Prediction: {status} ({prediction})")