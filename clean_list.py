import tldextract
from urllib.parse import urlparse

# --- PASTE YOUR LIST HERE ---
# (I've put your list in here for you)
KNOWN_LEGITIMATE_DOMAINS = [
    'google.com', 'wikipedia.org', 'youtube.com', 'facebook.com', 'twitter.com',
    'amazon.com', 'microsoft.com', 'apple.com', 'netflix.com', 'reddit.com',
    'linkedin.com', 'instagram.com', 'pinterest.com', 'ebay.com', 'walmart.com',
    'target.com', 'cnn.com', 'bbc.com', 'nytimes.com', 'theguardian.com',
    'washingtonpost.com', 'foxnews.com', 'huffpost.com', 'bloomberg.com',
    'forbes.com', 'techcrunch.com', 'wired.com', 'theverge.com', 'stackoverflow.com',
    'github.com', 'gitlab.com', 'bitbucket.org', 'mozilla.org', 'python.org',
    'w3schools.com', 'coursera.org', 'edx.org', 'udemy.com', 'khanacademy.org',
    'nasa.gov', 'spacex.com', 'tesla.com', 'bmw.com', 'mercedes-benz.com',
    'audi.com', 'toyota.com', 'honda.com', 'ford.com', 'chevrolet.com',
    'nike.com', 'adidas.com', 'zara.com', 'hm.com', 'etsy.com', 'airbnb.com',
    'booking.com', 'expedia.com', 'tripadvisor.com', 'yelp.com', 'opentable.com',
    'dominos.com', 'pizzahut.com', 'mcdonalds.com', 'starbucks.com', 'spotify.com',
    'pandora.com', 'apple.com', 'weather.com', 'accuweather.com', 'usatoday.com',
    'reuters.com', 'apnews.com', 'npr.org', 'pbs.org', 'nationalgeographic.com',
    'discovery.com', 'history.com', 'travelchannel.com', 'foodnetwork.com',
    'allrecipes.com', 'epicurious.com', 'seriouseats.com', 'healthline.com',
    'webmd.com', 'mayoclinic.org', 'who.int', 'cdc.gov', 'nih.gov', 'usa.gov',
    'gov.uk', 'canada.ca', 'australia.gov.au', 'europa.eu', 'un.org', 'worldbank.org',
    'imf.org', 'bing.com', 'duckduckgo.com', 'yahoo.com', 'aol.com', 'msn.com',
    'blogger.com', 'wordpress.com', 'medium.com', 'quora.com', 'paypal.com',
    'stripe.com', 'square.com', 'zoom.us', 'slack.com', 'trello.com', 'asana.com',
    'notion.so', 'evernote.com', 'dropbox.com', 'onedrive.live.com', 'icloud.com',
    'protonmail.com', 'gmail.com', 'outlook.live.com', 'mail.yahoo.com', 'protonvpn.com',
    'nordvpn.com', 'expressvpn.com', 'lastpass.com', '1password.com', 'dashlane.com',
    'autodesk.com', 'adobe.com', 'gimp.org', 'blender.org', 'figma.com', 'canva.com',
    'sketch.com', 'invisionapp.com', 'miro.com', 'lucidchart.com', 'draw.io',
    'openstreetmap.org', 'mapbox.com', 'esri.com', 'qgis.org', 'tableau.com',
    'powerbi.microsoft.com', 'looker.com', 'salesforce.com', 'hubspot.com',
    'zendesk.com', 'freshdesk.com', 'servicenow.com', 'atlassian.com', 'confluence.com',
    'monday.com', 'smartsheet.com', 'airtable.com', 'flickr.com', 'shutterstock.com',
    'gettyimages.com', 'unsplash.com', 'pexels.com', 'pixabay.com', 'istockphoto.com',
    'depositphotos.com', 'dreamstime.com', 'alamy.com', 'vectorstock.com', 'freepik.com',
    'flaticon.com', 'thenounproject.com', 'iconfinder.com', 'fontawesome.com',
    'materialui.com', 'react-icons.github.io', 'heroicons.com', 'tabler-icons.io',
    'simpleicons.org', 'devicon.dev', 'skillicons.dev', 'shields.io', 'badgen.net',
    'crates.io', 'rubygems.org', 'nuget.org', 'packagist.org', 'hex.pm', 'cocoapods.org',
    'libraries.io', 'atom.io', 'marketplace.visualstudio.com', 'chrome.google.com',
    'addons.mozilla.org', 'example.com', 'test.org', 'sub.domain.co.uk', 'blog.mysite.net',
    'shop.ecommerce.io', 'secure.banking.com', 'docs.cloudservice.app', 'learn.education.edu',
    'forum.community.org', 'support.company.info', 'portal.customer.biz', 'my.account.service.com',
    'app.mobileapp.xyz', 'data.analytics.ai', 'api.developer.tech', 'cdn.assets.net',
    'static.website.com', 'download.software.org', 'mail.google.com', 'calendar.google.com',
    'drive.google.com', 'photos.google.com', 'news.google.com', 'play.google.com',
    'meet.google.com', 'chat.google.com', 'voice.google.com', 'translate.google.com',
    'scholar.google.com', 'books.google.com', 'patents.google.com', 'groups.google.com',
    'sites.google.com', 'forms.google.com', 'sheets.google.com', 'slides.google.com',
    'docs.google.com', 'keep.google.com', 'jamboard.google.com', 'currents.google.com',
    'admin.google.com', 'console.cloud.google.com', 'firebase.google.com', 'ads.google.com',
    'analytics.google.com', 'tagmanager.google.com', 'search.google.com', 'developers.google.com',
    'careers.google.com', 'about.google', 'blog.google', 'investor.google.com', 'sustainability.google',
    'ai.google', 'health.google', 'waymo.com', 'verily.com', 'calicocare.com', 'deepmind.com',
    'x.company', 'gv.com', 'capitalg.com', 'sidewalklabs.com', 'intrin.sic', 'wing.com',
    'loon.com', 'chronicle.security', 'nest.com', 'fitbit.com', 'youtube.com', 'facebook.com',
    'protonmail.com', 'proton.me', 
    # --- Additional Domains to Add ---

    # Shopping & Services
    'shopify.com', 'bestbuy.com', 'homedepot.com', 'lowes.com', 'costco.com',
    'walgreens.com', 'cvs.com', 'craigslist.org', 'uber.com', 'lyft.com',
    'doordash.com', 'grubhub.com', 'instacart.com', 'chase.com', 
    'bankofamerica.com', 'wellsfargo.com', 'citibank.com', 'capitalone.com',
    'americanexpress.com', 'visa.com', 'mastercard.com',

    # Social & Content
    'tiktok.com', 'twitch.tv', 'discord.com', 'tumblr.com', 'spotify.com',
    'soundcloud.com', 'vimeo.com', 'dailymotion.com', 'imgur.com',

    # News & Media
    'wsj.com', 'usatoday.com', 'forbes.com', 'bloomberg.com',
    'businessinsider.com', 'espn.com', 'ign.com', 'gamespot.com',
    'cnet.com', 'rottentomatoes.com', 'imdb.com',

    # Tech & Software
    'godaddy.com', 'namecheap.com', 'cloudflare.com', 'fastly.com',
    'akamai.com', 'oracle.com', 'ibm.com', 'salesforce.com',
    'intuit.com', 'dell.com', 'hp.com', 'intel.com', 'amd.com', 'nvidia.com',
    'wordpress.org', 'joomla.org', 'drupal.org', 'wix.com', 'squarespace.com',

    # Government & Education
    'mit.edu', 'harvard.edu', 'stanford.edu', 'berkeley.edu',
    'cam.ac.uk', 'ox.ac.uk', 'who.int', 'cdc.gov', 'nih.gov'
]
# --- END OF YOUR LIST ---


def clean_domain_list(domains):
    """
    Parses a list of mixed URLs, subdomains, and domains,
    and returns a clean set of top-level domains.
    """
    cleaned_domains = set()
    
    for item in domains:
        # Handle full URLs like 'http://...'
        if item.startswith('http://') or item.startswith('https://'):
            domain = urlparse(item).hostname
        else:
            domain = item

        # Extract the registered domain
        # e.g., 'mail.google.com' -> 'google.com'
        # e.g., 'google.com' -> 'google.com'
        # e.g., 'sub.domain.co.uk' -> 'domain.co.uk'
        try:
            ext = tldextract.extract(domain)
            registered_domain = ext.top_domain_under_public_suffix
            
            if registered_domain:
                cleaned_domains.add(registered_domain)
            else:
                # Handle cases like 'localhost' or single names
                if '.' not in item:
                     print(f"Skipping invalid/local item: {item}")
                # It might be a TLD itself or a malformed entry
                elif domain:
                    cleaned_domains.add(domain.lower())

        except Exception as e:
            print(f"Could not parse '{item}': {e}")
            
    return sorted(list(cleaned_domains))

# --- Run the cleanup ---
cleaned_list = clean_domain_list(KNOWN_LEGITIMATE_DOMAINS)

# --- Print the new list ---
print("--- 🚀 Your Cleaned Domain List ---")
print("Copy this list and replace the old one in BOTH main.py and ml_model.py\n")
print(f"Total domains cleaned: {len(cleaned_list)}\n")

# Print in a format easy to copy back into Python
print("KNOWN_LEGITIMATE_DOMAINS = [")
for i, domain in enumerate(cleaned_list):
    print(f"    '{domain}',", end="\n")
print("]")