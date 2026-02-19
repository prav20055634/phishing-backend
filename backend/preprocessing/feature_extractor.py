import re
import tldextract
import numpy as np
import pandas as pd
from urllib.parse import urlparse, parse_qs
import math

class URLFeatureExtractor:
    def __init__(self):
        self.suspicious_words = [
            'secure','account','login','signin','verify',
            'update','confirm','banking','paypal','appleid',
            'amazon','netflix','password','validate','security'
        ]

    def extract_all_features(self, url):
        f = {}
        f['url_length'] = len(url)
        f['count_dots'] = url.count('.')
        f['count_hyphens'] = url.count('-')
        f['count_slash'] = url.count('/')
        f['count_question'] = url.count('?')
        f['count_equal'] = url.count('=')
        f['count_at'] = url.count('@')
        f['count_and'] = url.count('&')

        digits = sum(c.isdigit() for c in url)
        letters = sum(c.isalpha() for c in url)
        f['digit_ratio'] = digits / len(url) if len(url) > 0 else 0
        f['letter_ratio'] = letters / len(url) if len(url) > 0 else 0
        f['entropy'] = self.calculate_entropy(url)

        try:
            parsed = urlparse(url)
            ext = tldextract.extract(url)
            f['domain_length'] = len(ext.domain)
            f['subdomain_length'] = len(ext.subdomain)
            f['has_ip'] = 1 if re.match(
                r'^\d+\.\d+\.\d+\.\d+$', ext.domain) else 0
            f['suspicious_words_count'] = sum(
                1 for w in self.suspicious_words
                if w in ext.domain.lower()
                or w in ext.subdomain.lower())
            f['hyphen_in_domain'] = 1 if '-' in ext.domain else 0
            f['subdomain_count'] = len(
                ext.subdomain.split('.')) if ext.subdomain else 0
            f['uses_https'] = 1 if parsed.scheme == 'https' else 0
            path = parsed.path
            query = parsed.query
            f['path_length'] = len(path)
            f['path_depth'] = path.count('/')
            f['query_length'] = len(query)
            f['parameter_count'] = len(
                parse_qs(query)) if query else 0
            suspicious_path = [
                'login','signin','verify','update',
                'secure','account','confirm']
            f['suspicious_path_count'] = sum(
                1 for w in suspicious_path if w in path.lower())
        except:
            for key in ['domain_length','subdomain_length','has_ip',
                        'suspicious_words_count','hyphen_in_domain',
                        'subdomain_count','uses_https','path_length',
                        'path_depth','query_length','parameter_count',
                        'suspicious_path_count']:
                f[key] = 0

        shorteners = ['bit.ly','tinyurl','goo.gl','ow.ly']
        f['is_shortened'] = 1 if any(
            s in url for s in shorteners) else 0
        f['has_at_symbol'] = 1 if '@' in url else 0
        return f

    def calculate_entropy(self, text):
        if not text:
            return 0
        entropy = 0
        for i in range(256):
            char = chr(i)
            freq = text.count(char)
            if freq > 0:
                freq = float(freq) / len(text)
                entropy -= freq * math.log2(freq)
        return entropy

    def create_feature_vector(self, urls):
        features = [self.extract_all_features(url) for url in urls]
        return pd.DataFrame(features)