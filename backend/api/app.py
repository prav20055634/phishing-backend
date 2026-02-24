from flask import Flask, request, jsonify
from flask_cors import CORS
import re

app = Flask(__name__)
CORS(app)

def check_phishing_rules(url):
    url_lower = url.lower()
    phishing_indicators = 0

    # Suspicious keywords
    keywords = ['verify', 'account', 'update', 'confirm', 'secure',
                'banking', 'suspended', 'login', 'signin', 'credential',
                'validate', 'authenticate', 'alert', 'urgent', 'expire',
                'billing', 'password', 'recover', 'unlock', 'limited']
    for keyword in keywords:
        if keyword in url_lower:
            phishing_indicators += 1

    # Hyphens and dots
    if url_lower.count('-') >= 2:
        phishing_indicators += 2
    if url_lower.count('.') >= 4:
        phishing_indicators += 1

    # IP address
    import re
    if re.search(r'\d+\.\d+\.\d+\.\d+', url_lower):
        phishing_indicators += 5

    # Brand spoofing patterns
    brands = ['paypal', 'apple', 'microsoft', 'amazon', 'google',
              'netflix', 'facebook', 'instagram', 'twitter', 'linkedin',
              'outlook', 'office365', 'office', 'onedrive', 'teams',
              'bankofamerica', 'wellsfargo', 'chase', 'citibank', 'hdfc',
              'icici', 'sbi', 'ebay', 'walmart', 'fedex', 'dhl', 'ups']

    # Check brand + suspicious domain combination
    for brand in brands:
        if brand in url_lower:
            # Safe: brand is the actual domain
            safe_domains = [
                f'{brand}.com', f'{brand}.net', f'{brand}.org',
                f'www.{brand}.com', f'login.{brand}.com',
                f'account.{brand}.com', f'mail.{brand}.com',
                f'outlook.{brand}.com', f'office.{brand}.com'
            ]
            is_safe = any(url_lower.startswith(f'https://{d}') or
                         url_lower.startswith(f'http://{d}') for d in safe_domains)
            if not is_safe:
                phishing_indicators += 4

    # Microsoft specific patterns
    microsoft_phishing = [
        'microsoft-', '-microsoft', 'microsoft365', 'microsoftonline',
        'ms-verify', 'outlook-verify', 'office-verify', 'teams-verify',
        'office365-', '-office365', 'onedrive-', 'sharepoint-verify'
    ]
    for pattern in microsoft_phishing:
        if pattern in url_lower:
            phishing_indicators += 4

    # Generic phishing patterns
    phishing_patterns = [
        'security-verify', 'account-verify', 'secure-login',
        'verify-account', 'confirm-account', 'update-account',
        'account-update', 'login-verify', 'signin-verify',
        'account-suspended', 'account-locked', 'account-blocked',
        'unusual-activity', 'suspicious-activity', '-alert-',
        'free-gift', 'you-won', 'claim-prize', 'lucky-winner'
    ]
    for pattern in phishing_patterns:
        if pattern in url_lower:
            phishing_indicators += 4

    # Domain spoofing (brand.com.attacker.com)
    for brand in brands:
        if re.search(f'{brand}\\.com\\.[a-z]', url_lower):
            phishing_indicators += 8

    # Not HTTPS on sensitive page
    if not url_lower.startswith('https'):
        if any(w in url_lower for w in ['login', 'verify', 'account', 'banking', 'secure']):
            phishing_indicators += 2

    # Suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz',
                      '.top', '.click', '.link', '.online', '.site']
    for tld in suspicious_tlds:
        if url_lower.endswith(tld) or (tld + '/') in url_lower:
            phishing_indicators += 3

    return phishing_indicators >= 4