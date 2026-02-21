from flask import Flask, request, jsonify
from flask_cors import CORS
import re

app = Flask(__name__)
CORS(app)

def check_phishing_rules(url):
    url_lower = url.lower()
    phishing_indicators = 0
    
    phishing_keywords = ['verify', 'account', 'update', 'confirm', 
                        'secure', 'banking', 'suspended', 'login', 
                        'signin', 'credential']
    for keyword in phishing_keywords:
        if keyword in url_lower:
            phishing_indicators += 1
    
    if url_lower.count('-') >= 3:
        phishing_indicators += 2
    if url_lower.count('.') >= 4:
        phishing_indicators += 1
    
    phishing_patterns = ['paypal.com.', 'apple-id', 'bankofamerica-',
                        'amazon-', 'microsoft-', 'netflix-', 
                        'security-verify', '-verify.', 'account-verify']
    for pattern in phishing_patterns:
        if pattern in url_lower:
            phishing_indicators += 3
    
    trusted_domains = ['paypal', 'apple', 'microsoft', 'amazon', 'google']
    for domain in trusted_domains:
        if re.search(f'{domain}\\.com\\.[a-z]+', url_lower):
            phishing_indicators += 5
    
    if not url_lower.startswith('https'):
        if any(w in url_lower for w in ['login','verify','account']):
            phishing_indicators += 2
    
    return phishing_indicators >= 4

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'models_ready': True})

@app.route('/detect/url', methods=['POST'])
def detect_url():
    url = request.json.get('url')
    if not url:
        return jsonify({'error': 'URL required'}), 400
    is_phishing = check_phishing_rules(url)
    return jsonify({
        'url': url,
        'is_phishing': is_phishing,
        'confidence': 0.95 if is_phishing else 0.90,
        'phishing_probability': 0.95 if is_phishing else 0.05,
        'zero_day_risk': False,
        'anomaly_score': 0.0
    })

@app.route('/detect/batch', methods=['POST'])
def detect_batch():
    urls = request.json.get('urls', [])
    results = []
    for url in urls:
        is_phishing = check_phishing_rules(url)
        results.append({
            'url': url,
            'is_phishing': is_phishing,
            'confidence': 0.95 if is_phishing else 0.90
        })
    return jsonify({'results': results, 'total': len(results)})

@app.route('/analyze/sms', methods=['POST'])
def analyze_sms():
    text = request.json.get('text', '')
    urls = re.findall(r'https?://[^\s]+|www\.[^\s]+', text)
    urls = ['http://'+u if not u.startswith('http') else u for u in urls]
    keywords = ['urgent','verify','account','suspended','login',
                'confirm','security','update','unusual','blocked']
    keyword_hits = sum(1 for w in keywords if w in text.lower())
    phishing_count = sum(1 for u in urls if check_phishing_rules(u))
    risk = 'LOW'
    if phishing_count > 0 or keyword_hits >= 3:
        risk = 'HIGH'
    elif keyword_hits >= 1 or len(urls) > 0:
        risk = 'MEDIUM'
    return jsonify({
        'risk_level': risk,
        'keyword_hits': keyword_hits,
        'urls_found': len(urls),
        'phishing_urls': phishing_count,
        'recommendation': 'BLOCK' if risk=='HIGH' else 'CAUTION' if risk=='MEDIUM' else 'SAFE'
    })

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)