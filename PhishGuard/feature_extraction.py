from urllib.parse import urlparse
import re


def extract_features(url):

    features = []

    # 1. Having IP Address
    ip_pattern = re.compile(
        r'^(?:http[s]?://)?'
        r'((\d{1,3}\.){3}\d{1,3})'
    )

    if ip_pattern.search(url):
        features.append(1)
    else:
        features.append(-1)

    # 2. URL Length
    if len(url) < 54:
        features.append(-1)
    elif 54 <= len(url) <= 75:
        features.append(0)
    else:
        features.append(1)

    # 3. HTTPS
    if url.startswith("https"):
        features.append(-1)
    else:
        features.append(1)

    return features
