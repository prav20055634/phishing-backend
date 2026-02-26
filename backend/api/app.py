from flask import Flask, request, jsonify
from flask_cors import CORS
import re
from urllib.parse import urlparse, unquote, parse_qs
import math

app = Flask(__name__)
CORS(app)

def decode_url_fully(url):
    try:
        decoded = url
        for _ in range(5):
            new_decoded = unquote(decoded)
            if new_decoded == decoded:
                break
            decoded = new_decoded
        return decoded
    except:
        return url

def get_entropy(text):
    if not text:
        return 0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0
    length = len(text)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

def check_encoded_url(url):
    score = 0
    reasons = []
    percent_matches = re.findall(r'%[0-9a-fA-F]{2}', url)
    if len(percent_matches) > 3:
        score += 4
        reasons.append(f"Heavy percent encoding ({len(percent_matches)} encoded chars)")
    decoded = decode_url_fully(url)
    decoded_lower = decoded.lower()
    phishing_keywords = ['paypal','apple','microsoft','amazon','google','netflix','facebook',
        'instagram','twitter','linkedin','outlook','office365','bankofamerica','wellsfargo',
        'chase','citibank','hdfc','icici','sbi','verify','account','login','secure',
        'suspended','update','confirm','credential','banking','password']
    hits = [k for k in phishing_keywords if k in decoded_lower]
    if hits:
        score += len(hits) * 2
        reasons.append(f"Decoded URL contains: {', '.join(hits[:3])}")
    if 'xn--' in url.lower():
        score += 6
        reasons.append("Punycode/IDN homograph attack (xn-- pattern)")
    if re.search(r'0x[0-9a-fA-F]{8}', url):
        score += 7
        reasons.append("Hex encoded IP address in URL")
    if re.search(r'0\d{9,}', url):
        score += 6
        reasons.append("Octal encoded IP address detected")
    b64_matches = re.findall(r'[A-Za-z0-9+/]{30,}={0,2}', url)
    if b64_matches:
        score += 3
        reasons.append("Base64 encoded data in URL")
    try:
        if any(ord(c) > 127 for c in url):
            score += 5
            reasons.append("Non-ASCII unicode characters in URL")
    except:
        pass
    if '%25' in url:
        score += 5
        reasons.append("Double percent encoding detected (%25)")
    if '%00' in url or '\x00' in url:
        score += 8
        reasons.append("Null byte injection detected")
    return score >= 4, score, reasons

def check_compromised_site(url):
    score = 0
    reasons = []
    try:
        url_lower = url.lower()
        parsed = urlparse(url_lower)
        domain = parsed.netloc.replace('www.', '')
        path = parsed.path
        query = parsed.query
        full_path = path + '?' + query if query else path
        free_hosting = ['wordpress.com','blogspot.com','weebly.com','wix.com',
            'squarespace.com','github.io','netlify.app','vercel.app','herokuapp.com',
            '000webhostapp.com','pages.dev','firebaseapp.com','web.app','glitch.me',
            'repl.co','surge.sh','biz.nf','ucoz.com','jimdo.com']
        for host in free_hosting:
            if host in domain:
                suspicious_paths = ['paypal','apple','microsoft','amazon','google','login',
                    'verify','account','secure','banking','signin','update','confirm',
                    'password','credential']
                hits = [p for p in suspicious_paths if p in full_path]
                if hits:
                    score += 5
                    reasons.append(f"Free hosting '{host}' with phishing path: {hits}")
        if re.search(r'(redirect|return|next|goto|url|link)=https?://', url_lower):
            score += 6
            reasons.append("Open redirect pattern in URL")
        try:
            params = parse_qs(query)
            open_redirect_params = ['redirect','return','returnurl','next','goto','url','link','target']
            for param in open_redirect_params:
                if param in params:
                    val = params[param][0] if params[param] else ''
                    if val.startswith('http') or val.startswith('//'):
                        score += 7
                        reasons.append(f"Open redirect: {param}={val[:40]}")
        except:
            pass
        php_phishing = ['login.php','signin.php','verify.php','account.php','secure.php',
            'update.php','confirm.php','bank.php','paypal.php','apple.php','microsoft.php']
        for php in php_phishing:
            if php in url_lower:
                score += 5
                reasons.append(f"Phishing PHP file: {php}")
        path_segments = [p for p in path.split('/') if p]
        if path_segments:
            max_len = max(len(p) for p in path_segments)
            if max_len > 35:
                score += 3
                reasons.append(f"Suspiciously long random path ({max_len} chars)")
        if path and get_entropy(path) > 4.2:
            score += 3
            reasons.append(f"High entropy path (entropy={get_entropy(path):.2f})")
        subdomain_count = domain.count('.') - 1 if domain else 0
        if subdomain_count >= 3:
            score += 4
            reasons.append(f"Excessive subdomains ({subdomain_count})")
        brands_in_path = ['paypal','apple','microsoft','amazon','google','netflix',
            'facebook','instagram','bankofamerica','wellsfargo','chase','hdfc','icici','sbi']
        for brand in brands_in_path:
            if brand in path and brand not in domain:
                score += 5
                reasons.append(f"Brand '{brand}' in path but NOT in domain")
        if '@' in url_lower:
            score += 6
            reasons.append("@ symbol in URL — credential trick")
    except:
        pass
    return score >= 4, score, reasons

def check_typosquatting(url):
    score = 0
    reasons = []
    url_lower = url.lower()
    try:
        parsed = urlparse(url_lower)
        domain = parsed.netloc.replace('www.', '').split(':')[0]
        domain_base = domain.split('.')[0] if '.' in domain else domain
        typo_patterns = {
            'paypal':    ['paypa1','paypall','paaypal','payapl','pyapal','paypel','paypl','paupal'],
            'google':    ['g00gle','gooogle','googel','gogle','g0ogle','googIe','googlr'],
            'microsoft': ['micros0ft','microsft','microsobt','mircosoft','micosoft','microft'],
            'amazon':    ['arnazon','amaz0n','amazoon','amazn','arnaz0n','anazon','amzon'],
            'apple':     ['app1e','aple','appie','applle','aplle'],
            'facebook':  ['faceb00k','facebok','facbook','faceboook'],
            'netflix':   ['netfl1x','netfix','netlfix','netfllx'],
            'instagram': ['instagramm','lnstagram','instagran'],
            'twitter':   ['twlter','twitterr','twiter','tw1tter'],
            'linkedin':  ['linkedln','linkeldin','linkediin'],
            'hdfc':      ['hdfcbank','hdfcbanks','hdfc-bank'],
            'icici':     ['icicii','icicl','ic1ci'],
            'sbi':       ['sbionline','sbi-bank','sbii'],
        }
        for brand, typos in typo_patterns.items():
            for typo in typos:
                if typo in domain_base:
                    score += 8
                    reasons.append(f"Typosquatting: '{typo}' mimics '{brand}'")
        legit_brands = ['paypal','google','microsoft','amazon','apple',
                         'facebook','netflix','instagram','twitter','linkedin']
        digit_subs = {'1':'l','0':'o','3':'e','4':'a','5':'s'}
        normalized = domain_base
        for digit, letter in digit_subs.items():
            normalized = normalized.replace(digit, letter)
        if normalized != domain_base:
            for brand in legit_brands:
                if brand == normalized and brand not in domain_base:
                    score += 7
                    reasons.append(f"Digit substitution: '{domain_base}' looks like '{brand}'")
        for brand in legit_brands:
            if len(domain_base) > 3 and abs(len(domain_base) - len(brand)) <= 2:
                matches = sum(a == b for a, b in zip(domain_base, brand))
                similarity = matches / max(len(domain_base), len(brand))
                if similarity > 0.8 and domain_base != brand:
                    score += 5
                    reasons.append(f"Near-match domain: '{domain_base}' resembles '{brand}'")
                    break
    except:
        pass
    return score >= 5, score, reasons

def check_phishing_rules(url):
    score = 0
    reasons = []
    url_lower = url.lower()
    try:
        parsed = urlparse(url_lower)
        domain = parsed.netloc.replace('www.', '')
        path = parsed.path
    except:
        domain = ''
        path = ''

    keywords = ['verify','account','update','confirm','secure','banking','suspended','login',
        'signin','credential','validate','authenticate','alert','urgent','expire','billing',
        'password','recover','unlock','limited','unusual','blocked','restrict','prize',
        'winner','free-gift','claim','reward','lucky']
    hits = [k for k in keywords if k in url_lower]
    if hits:
        score += len(hits)
        if len(hits) >= 2:
            reasons.append(f"Multiple suspicious keywords: {hits[:4]}")

    hyphen_count = url_lower.count('-')
    if hyphen_count >= 3:
        score += 3
        reasons.append(f"Excessive hyphens ({hyphen_count})")
    elif hyphen_count >= 2:
        score += 2

    dot_count = url_lower.count('.')
    if dot_count >= 5:
        score += 3
        reasons.append(f"Excessive dots ({dot_count}) — subdomain spoofing")
    elif dot_count >= 4:
        score += 1

    if re.search(r'(?:^|[/@])(\d{1,3}\.){3}\d{1,3}', url_lower):
        score += 8
        reasons.append("Raw IP address used instead of domain name")

    brands = ['paypal','apple','microsoft','amazon','google','netflix','facebook',
        'instagram','twitter','linkedin','outlook','office365','office','onedrive',
        'teams','sharepoint','bankofamerica','wellsfargo','chase','citibank','barclays',
        'hdfc','icici','sbi','axis','kotak','ebay','fedex','dhl','ups','usps',
        'spotify','discord','steam','roblox']
    safe_domains = []
    for b in brands:
        safe_domains.extend([f'{b}.com',f'www.{b}.com',f'login.{b}.com',f'account.{b}.com',
            f'mail.{b}.com',f'secure.{b}.com',f'accounts.{b}.com',f'id.{b}.com',
            f'signin.{b}.com',f'my.{b}.com',f'support.{b}.com',f'help.{b}.com'])
    for brand in brands:
        if brand in url_lower:
            is_safe = any(
                url_lower.startswith(f'https://{d}/') or url_lower.startswith(f'http://{d}/') or
                url_lower == f'https://{d}' or url_lower == f'http://{d}'
                for d in safe_domains)
            if not is_safe:
                score += 5
                reasons.append(f"Brand '{brand}' in suspicious domain context")
                break

    ms_patterns = ['microsoft-','-microsoft','microsoft365','microsoftonline-','ms-verify',
        'outlook-verify','office-verify','teams-verify','office365-','-office365',
        'onedrive-','sharepoint-verify','ms-secure','msoffice']
    for pattern in ms_patterns:
        if pattern in url_lower:
            score += 5
            reasons.append(f"Microsoft phishing pattern: '{pattern}'")
            break

    phishing_combos = ['security-verify','account-verify','secure-login','login-secure',
        'verify-account','confirm-account','update-account','account-update','login-verify',
        'signin-verify','account-suspended','account-locked','account-blocked',
        'unusual-activity','suspicious-activity','security-alert','billing-update',
        'payment-verify','card-verify','bank-verify','verify-identity','confirm-identity']
    for combo in phishing_combos:
        if combo in url_lower:
            score += 5
            reasons.append(f"Phishing combo pattern: '{combo}'")
            break

    for brand in brands:
        if re.search(f'{brand}\\.com\\.[a-z]', url_lower):
            score += 10
            reasons.append(f"Domain spoofing: '{brand}.com.xxxx' pattern")
            break

    if not url_lower.startswith('https'):
        sensitive = ['login','verify','account','banking','secure','password','credential','payment']
        hits2 = [w for w in sensitive if w in url_lower]
        if hits2:
            score += 3
            reasons.append(f"HTTP (not HTTPS) on sensitive page: {hits2}")

    suspicious_tlds = ['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.click',
        '.link','.online','.site','.pw','.cc','.su','.ws']
    for tld in suspicious_tlds:
        if domain.endswith(tld) or (tld + '/') in url_lower:
            score += 4
            reasons.append(f"Suspicious TLD: '{tld}'")
            break

    if len(url) > 150:
        score += 2
        reasons.append(f"Very long URL ({len(url)} chars)")

    if '@' in url_lower:
        score += 6
        reasons.append("@ symbol in URL — credential trick")

    if '//' in path:
        score += 3
        reasons.append("Double slash in path — evasion technique")

    return score >= 4, score, reasons

def analyze_url(url):
    if not url or len(url.strip()) < 4:
        return {'error': 'Invalid URL'}
    url = url.strip()
    decoded_url = decode_url_fully(url)
    phishing_result, phishing_score, phishing_reasons = check_phishing_rules(decoded_url)
    encoded_result, encoded_score, encoded_reasons = check_encoded_url(url)
    compromised_result, comp_score, comp_reasons = check_compromised_site(decoded_url)
    typo_result, typo_score, typo_reasons = check_typosquatting(decoded_url)
    total_score = phishing_score + encoded_score + comp_score + typo_score
    all_reasons = phishing_reasons + encoded_reasons + comp_reasons + typo_reasons
    is_phishing = phishing_result or encoded_result or compromised_result or typo_result
    if encoded_result:
        threat_type = 'Encoded URL Attack'
    elif typo_result:
        threat_type = 'Typosquatting Attack'
    elif compromised_result:
        threat_type = 'Compromised Site'
    elif phishing_result:
        if '@' in url:
            threat_type = 'Credential Trick'
        elif re.search(r'\d+\.\d+\.\d+\.\d+', url):
            threat_type = 'IP-Based Phishing'
        else:
            threat_type = 'Brand Spoofing Phishing'
    else:
        threat_type = 'None'
    confidence = min(0.99, 0.50 + (total_score * 0.03)) if is_phishing else max(0.70, 0.99 - (total_score * 0.05))
    zero_day = encoded_result or compromised_result or (total_score > 15 and not phishing_result)
    return {
        'url': url,
        'decoded_url': decoded_url if decoded_url != url else None,
        'is_phishing': is_phishing,
        'confidence': round(confidence, 2),
        'phishing_probability': round(confidence, 2) if is_phishing else round(1 - confidence, 2),
        'total_score': total_score,
        'zero_day_risk': zero_day,
        'anomaly_score': round(min(1.0, total_score / 20), 2),
        'threat_type': threat_type,
        'is_encoded': encoded_result,
        'is_compromised': compromised_result,
        'is_typosquatting': typo_result,
        'reasons': all_reasons[:6],
        'modules': {
            'phishing_rules': {'triggered': phishing_result, 'score': phishing_score},
            'encoded_url': {'triggered': encoded_result, 'score': encoded_score},
            'compromised_site': {'triggered': compromised_result, 'score': comp_score},
            'typosquatting': {'triggered': typo_result, 'score': typo_score},
        }
    }

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'models_ready': True, 'version': '3.0',
        'modules': ['phishing_rules', 'encoded_url', 'compromised_site', 'typosquatting', 'zero_day']})

@app.route('/detect/url', methods=['POST'])
def detect_url():
    data = request.json
    if not data or 'url' not in data:
        return jsonify({'error': 'URL required'}), 400
    return jsonify(analyze_url(data['url']))

@app.route('/detect/batch', methods=['POST'])
def detect_batch():
    data = request.json
    urls = data.get('urls', [])
    if not urls:
        return jsonify({'error': 'URLs list required'}), 400
    results = [analyze_url(url) for url in urls[:20]]
    phishing_count = sum(1 for r in results if r.get('is_phishing'))
    return jsonify({'results': results, 'total': len(results),
        'phishing_count': phishing_count, 'safe_count': len(results) - phishing_count})

@app.route('/analyze/sms', methods=['POST'])
def analyze_sms():
    data = request.json
    text = data.get('text', '')
    if not text:
        return jsonify({'error': 'Text required'}), 400
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    www_pattern = r'www\.[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, text) + \
           ['http://' + u for u in re.findall(www_pattern, text)]
    urls = list(set(urls))
    url_results = [analyze_url(u) for u in urls]
    phishing_urls = [r for r in url_results if r.get('is_phishing')]
    encoded_urls = [r for r in url_results if r.get('is_encoded')]
    high_risk_keywords = ['urgent','suspended','blocked','locked','expired','immediately',
        'action required','verify now','click here','limited time','prize','winner',
        'free gift','congratulations','your account','unauthorized','unusual activity','security alert']
    medium_keywords = ['verify','account','login','confirm','update','security','password','credential','billing']
    text_lower = text.lower()
    high_hits = [k for k in high_risk_keywords if k in text_lower]
    medium_hits = [k for k in medium_keywords if k in text_lower]
    keyword_hits = len(high_hits) + len(medium_hits)
    if len(phishing_urls) > 0 or len(encoded_urls) > 0 or len(high_hits) >= 2:
        risk = 'HIGH'
    elif keyword_hits >= 2 or len(urls) > 0:
        risk = 'MEDIUM'
    else:
        risk = 'LOW'
    return jsonify({'risk_level': risk, 'keyword_hits': keyword_hits,
        'high_risk_keywords': high_hits[:5], 'urls_found': len(urls),
        'phishing_urls': len(phishing_urls), 'encoded_urls': len(encoded_urls),
        'url_analysis': url_results,
        'recommendation': 'BLOCK' if risk == 'HIGH' else 'CAUTION' if risk == 'MEDIUM' else 'SAFE',
        'is_phishing': risk == 'HIGH'})

@app.route('/test', methods=['GET'])
def test_detection():
    test_cases = [
        ('http://paypal.com.verify-account.net/login', True, 'Brand Spoofing'),
        ('http://192.168.1.1/banking/login', True, 'IP Address'),
        ('http://%70%61%79%70%61%6C-verify.com/login', True, 'Encoded URL'),
        ('https://mysite.wordpress.com/paypal/verify.php', True, 'Compromised Site'),
        ('http://paypa1.com/login', True, 'Typosquatting'),
        ('https://www.google.com', False, 'Safe'),
        ('https://www.amazon.com/orders', False, 'Safe'),
    ]
    results = []
    for url, expected, label in test_cases:
        result = analyze_url(url)
        status = 'CORRECT' if result['is_phishing'] == expected else 'WRONG'
        results.append({'url': url, 'label': label, 'expected': expected,
            'got': result['is_phishing'], 'status': status, 'score': result['total_score'],
            'threat_type': result['threat_type']})
    correct = sum(1 for r in results if r['status'] == 'CORRECT')
    return jsonify({'accuracy': f'{correct}/{len(results)}', 'results': results})

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)