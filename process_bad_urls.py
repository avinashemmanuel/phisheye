import pandas as pd
import os
import re
from urllib.parse import urlparse

# DEFINE PATHS
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
URLHAUS_FILE = os.path.join(DATA_DIR, 'urlhaus.txt')
OPENPHISH_FILE = os.path.join(DATA_DIR, 'openphish.txt')
OUTPUT_BAD_URLS_CSV = os.path.join(DATA_DIR, 'bad_combined_urls.csv')

def load_and_process_url_list(filepath, source_name):
    """
    Loads URLs from a text file, cleans them, and returns a DataFrame.
    Assumes one URL per line.
    """
    urls = []
    if not os.path.exists(filepath):
        print(f"Warning: {source_name} file not found at {filepath}. Skipping.")
        return pd.DataFrame(columns=['URL', 'Label'])
    
    print(f"Loading URLs from {source_name}: {filepath}")
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            # Skip comments or empty lines
            if not line or line.startswith('#') or line.startswith('//'):
                continue

            # Basic URL validation (can be expanded)
            # Ensure it looks like a URL, not just random text
            if re.match(r'https?://[^\s/$.?#].[^\s]*$', line):
                urls.append(line)
            # For URLHaus, sometimes they include a CSV like format 
            # so we might need to parse if it's not just raw URLs
            # For now, assuming raw URLs. If the file is CSV we'll adjust
            elif ',' in line and 'http' in line: # Simple check for CSV-like line
                parts = line.split(',')
                for part in parts:
                    if re.match(r'https?://[^\s/$.?#].[^\s]*$', part.strip()):
                        urls.append(part.strip())
                        break # Take the first valid URL in a CSV line

    print(f"    Found {len(urls)} potential URLs from {source_name}")
    return pd.DataFrame({'URL': urls, 'Label': 'bad'})

def main ():
    os.makedirs(DATA_DIR, exist_ok=True)

    all_bad_urls_df = pd.DataFrame(columns=['URL', 'Label'])

    # Process URLHaus data
    urlhaus_df = load_and_process_url_list(URLHAUS_FILE, "URLhaus")
    all_bad_urls_df = pd.concat([all_bad_urls_df, urlhaus_df], ignore_index=True)

    # Process OpenPhish data
    openphish_df = load_and_process_url_list(OPENPHISH_FILE, "OpenPhish")
    all_bad_urls_df = pd.concat([all_bad_urls_df, openphish_df], ignore_index=True)

    # Remove duplicates
    initial_count = len(all_bad_urls_df)
    all_bad_urls_df.drop_duplicates(subset=['URL'], inplace=True)
    final_count = len(all_bad_urls_df)
    print(f"\nRemoved {initial_count - final_count} dupliucate bad URLs.")
    print(f"Total unique bad URLs collected: {final_count}")

    # Save the combined bad URLs
    all_bad_urls_df.to_csv(OUTPUT_BAD_URLS_CSV, index=False)
    print(f"Combined bad URLs saved to {OUTPUT_BAD_URLS_CSV}")

if __name__ == "__main__":
    main()