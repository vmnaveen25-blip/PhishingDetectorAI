import requests
from bs4 import BeautifulSoup
from backend.feature_extractor import extract_features

url = "http://www.google.com"
features =extract_features(url)
for k, v in features.items():
    print(f"{k}: {v}") 