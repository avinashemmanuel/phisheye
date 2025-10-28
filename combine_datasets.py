import pandas as pd
import os

# Define paths
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')

ORIGINAL_PHISHING_DATA = os.path.join(DATA_DIR, 'phishing_site_urls.csv')
GOOD_WIKIPEDIA_URLS = os.path.join(DATA_DIR, 'good_wikipedia_urls.csv')
BAD_COMBINED_URLS = os.path.join(DATA_DIR, 'bad_combined_urls.csv')

FINAL_DATASET_CSV = os.path.join(DATA_DIR, 'final_url_dataset.csv')

def main():
    all_data = []

    # 1. Load Original Phishing Dataset
    if os.path.exists(ORIGINAL_PHISHING_DATA):
        print(f"Loading original dataset: {ORIGINAL_PHISHING_DATA}")
        df_original = pd.read_csv(ORIGINAL_PHISHING_DATA)
        df_original.columns = ['url', 'Label'] 
        # Map labels: 'good' -> 0, 'bad' -> 1
        df_original['Label'] = df_original['Label'].map({'good': 0, 'bad': 1})
        all_data.append(df_original)
        print(f"    Loaded {len(df_original)} URLs from original dataset.")
    else:
        print(f"Warning: Original phishing dataset not found at {ORIGINAL_PHISHING_DATA}. Skipping.")

    # 2. Load Good Wikipedia URLs
    if os.path.exists(GOOD_WIKIPEDIA_URLS):
        print(f"Loading good Wikipedia URLs: {GOOD_WIKIPEDIA_URLS}")
        df_good_wiki = pd.read_csv(GOOD_WIKIPEDIA_URLS)
        df_good_wiki.columns = ['URL', 'Label']
        # Map labels: 'good' -> 0
        df_good_wiki['Label'] = df_good_wiki['Label'].map({'good': 0})
        all_data.append(df_good_wiki)
        print(f"    Loaded {len(df_good_wiki)} URLs from Wikipedia.")
    else:
        print(f"Warning: Good Wikipedia URLs not found at {GOOD_WIKIPEDIA_URLS}. Skipping.")

    # 3. Load Combined Bad URLs (OpenPhish + URLHaus)
    if os.path.exists(BAD_COMBINED_URLS):
        print(f"Loading combined bad URLs: {BAD_COMBINED_URLS}")
        df_bad_combined = pd.read_csv(BAD_COMBINED_URLS)
        df_bad_combined.columns = ['URL', 'Label']
        # Map labels: 'bad' -> 1
        df_bad_combined['Label'] = df_bad_combined['Label'].map({'bad': 1})
        all_data.append(df_bad_combined)
        print(f"    Loaded {len(df_bad_combined)} URLs from combined bad sources.")
    else:
        print(f"Warning: Combined bad URLs not found at {BAD_COMBINED_URLS}. Skipping.")

    if not all_data:
        print("No datasets found to combine. Exiting.")
        return
    
    # Concatenate all DataFrames
    combined_df = pd.concat(all_data, ignore_index=True)
    print(f"\nTotal URLs before de-duplication: {len(combined_df)}")

    # Remove duplicates
    initial_count = len(combined_df)
    combined_df.drop_duplicates(subset=['URL'], inplace=True)
    final_count = len(combined_df)
    print(f"Removed {initial_count - final_count} duplicate URLs.")

    # Display label distribution 
    print("\nLabel distribution in final dataset:")
    print(combined_df['Label'].value_counts())

    # Save the final dataset 
    combined_df.to_csv(FINAL_DATASET_CSV, index=False)
    print(f"\nFinal Combined Dataset saved to {FINAL_DATASET_CSV}")

if __name__ == "__main__":
    main()