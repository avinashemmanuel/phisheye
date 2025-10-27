import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import pandas as pd
import os
import time
from collections import deque

def scrape_wikipedia_urls(start_url, num_urls_to_collect=5000, max_depth=3):
    collected_urls = set()
    visited_urls = set() # Tracks URLs we've attempted to fetch/parse
    urls_to_visit = deque([(start_url, 0)])

    print(f"Starting URL scraping from: {start_url}")

    valid_wiki_domains = {
        'en.wikipedia.org', 'www.wikipedia.org', 'wikipedia.org',
    }

    # --- ADDED: User-Agent header ---
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        # You can use other common User-Agent strings as well.
        # It's good practice to also include an email or project link if you're doing extensive scraping,
        # but for this scale, a standard browser UA is usually sufficient.
    }

    while urls_to_visit and len(collected_urls) < num_urls_to_collect:
        current_url, current_depth = urls_to_visit.popleft()

        print(f"\n--- Processing: {current_url} (Depth: {current_depth}) ---")

        if current_url in visited_urls:
            print(f"  Skipping (already visited): {current_url}")
            continue

        visited_urls.add(current_url) # Mark as visited for processing

        # Add to collected_urls ONLY if it meets criteria for a "good" URL
        parsed_current_url = urlparse(current_url)
        
        is_collectible = False
        if parsed_current_url.scheme in ['http', 'https'] and \
           parsed_current_url.netloc in valid_wiki_domains and \
           parsed_current_url.path.startswith('/wiki/') and \
           not parsed_current_url.path.startswith('/wiki/File:') and \
           not parsed_current_url.path.startswith('/wiki/Help:') and \
           not parsed_current_url.path.startswith('/wiki/Special:') and \
           not parsed_current_url.path.startswith('/wiki/Portal:') and \
           not parsed_current_url.path.startswith('/wiki/Category:') and \
           not parsed_current_url.path.startswith('/wiki/Template:') and \
           not parsed_current_url.path.startswith('/wiki/Talk:') and \
           not parsed_current_url.path.startswith('/wiki/User:') and \
           not parsed_current_url.path.endswith(('.svg', '.png', '.jpg', '.gif')) and \
           not parsed_current_url.fragment:
            is_collectible = True
            
        if is_collectible:
            collected_urls.add(current_url)
            print(f"  Collected ({len(collected_urls)}/{num_urls_to_collect}): {current_url}")
        else:
            print(f"  NOT COLLECTIBLE: {current_url}")
            # Detailed reason for not collecting:
            if parsed_current_url.scheme not in ['http', 'https']: print(f"    - Bad scheme: {parsed_current_url.scheme}")
            if parsed_current_url.netloc not in valid_wiki_domains: print(f"    - Bad domain: {parsed_current_url.netloc}")
            if not parsed_current_url.path.startswith('/wiki/'): print(f"    - Path not /wiki/: {parsed_current_url.path}")
            if parsed_current_url.path.startswith('/wiki/File:'): print(f"    - Is File page")
            if parsed_current_url.path.startswith('/wiki/Help:'): print(f"    - Is Help page")
            if parsed_current_url.path.startswith('/wiki/Special:'): print(f"    - Is Special page")
            if parsed_current_url.path.startswith('/wiki/Portal:'): print(f"    - Is Portal page")
            if parsed_current_url.path.startswith('/wiki/Category:'): print(f"    - Is Category page")
            if parsed_current_url.path.startswith('/wiki/Template:'): print(f"    - Is Template page")
            if parsed_current_url.path.startswith('/wiki/Talk:'): print(f"    - Is Talk page")
            if parsed_current_url.path.startswith('/wiki/User:'): print(f"    - Is User page")
            if parsed_current_url.path.endswith(('.svg', '.png', '.jpg', '.gif')): print(f"    - Is image file")
            if parsed_current_url.fragment: print(f"    - Has fragment")


        if current_depth >= max_depth:
            print(f"  Max depth reached ({current_depth}/{max_depth}). Not exploring further.")
            continue

        try:
            time.sleep(0.1)
            print(f"  Fetching: {current_url}")
            # --- MODIFIED: Pass headers to requests.get ---
            response = requests.get(current_url, headers=headers, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            print(f"  Successfully fetched and parsed {current_url}. Found {len(soup.find_all('a', href=True))} links.")

            for link in soup.find_all('a', href=True):
                href = link['href']
                absolute_url = urljoin(current_url, href)
                parsed_link_url = urlparse(absolute_url)

                # --- DEBUGGING LINK FOLLOWING LOGIC ---
                is_followable = False
                if parsed_link_url.scheme in ['http', 'https'] and \
                   parsed_link_url.netloc in valid_wiki_domains and \
                   parsed_link_url.path.startswith('/wiki/') and \
                   not parsed_link_url.path.startswith('/wiki/File:') and \
                   not parsed_link_url.path.startswith('/wiki/Special:') and \
                   not parsed_link_url.fragment and \
                   absolute_url not in visited_urls:
                    is_followable = True
                
                if is_followable:
                    urls_to_visit.append((absolute_url, current_depth + 1))
                    # print(f"    + Added to queue: {absolute_url}")
                else:
                    # print(f"    - NOT ADDED to queue: {absolute_url}")
                    pass # Keep this commented for now, as it will be too verbose

        except requests.exceptions.RequestException as e:
            print(f"  ERROR: Request failed for {current_url}: {e}")
            pass
        except Exception as e:
            print(f"  ERROR: General error processing {current_url}: {e}")
            pass

    print(f"\nFinished scraping. Collected {len(collected_urls)} unique URLs.")
    return list(collected_urls)

if __name__ == "__main__":
    start_wikipedia_url = "https://en.wikipedia.org/wiki/Python_(programming_language)" 
    
    good_urls = scrape_wikipedia_urls(start_wikipedia_url, num_urls_to_collect=5000, max_depth=3)

    data_dir = os.path.join(os.path.dirname(__file__), 'data')
    os.makedirs(data_dir, exist_ok=True)
    
    df_good = pd.DataFrame({'URL': good_urls, 'Label': 'good'})
    output_path = os.path.join(data_dir, 'good_wikipedia_urls.csv')
    df_good.to_csv(output_path, index=False)
    print(f"Good URLs saved to {output_path}")