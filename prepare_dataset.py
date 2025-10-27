import pandas as pd
import os
import re
from urllib.parse import urlparse

#DEFINE PATHS
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
RAW_PHISHING_DATASET_PATH = os.path.join(DATA_DIR, 'phishing_site_urls.csv') # The original dataset
OPENPHISH_PATH = os.path.join(DATA_DIR, 'openphish.txt')
URLHAUS_PATH = os.path.join(DATA_DIR, 'urlhaus.txt')
