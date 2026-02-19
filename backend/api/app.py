from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import joblib
import os, sys, re

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from preprocessing.feature_extractor import URLFeatureExtractor

app = Flask(__name__)
CORS(app)

print("Loading models...")
try:
    detector = joblib.load('models_saved/detector.pkl')
    zero_day = joblib.load('models_saved/zero_day.pkl')
    support_df = pd.read_csv('models_saved/support_set.csv')
    detector.support_urls = support_df['url'].tolist()
    detector.support_labels = support_df['label'].tolist()
    extractor = URLFeatureExtractor()
    print(f"Ready! Support: {len(detector.support_urls)} examples")
    models_ready = True
except Exception as e:
    print(f"ERROR: {e}")
    print("Run train_pipeline.py first!")
    models_ready = False

def check_phishing_rules(url, features):
    """Rule-based phishing detection"""
    url_lower = url.lower()
    phishing_indicators = 0
    
    # Check 1: Suspicious keywords
    phishing_keywords = [
        'verify', 'account', 'update', 'confirm', 'secure',
        'banking', 'suspended', 'login', 'signin', 'credential'
    ]
    for keyword in phishing_keywords:
        if keyword in url_lower:
            phishing_indicators += 1
    
    # Check 2: Multiple hyphens
    if url_lower.count('-') >= 3:
        phishing_indicators += 2
    
    # Check 3: Multiple dots
    if url_lower.count('.') >= 4:
        phishing_indicators += 1
    
    # Check 4: IP address
    if features.get('has_ip', 0) == 1:
        phishing_indicators += 3
    
    # Check 5: Known phishing patterns
    phishing_patterns = [
        'paypal.com.', 'apple-id', 'appleid.',
        'bankofamerica-', 'amazon-', 'microsoft-',
        'netflix-', 'security-verify', '-verify.',
        'account-verify', 'login-', '-login.',
        'update.', '-update.', 'suspended-'
    ]
    for pattern in phishing_patterns:
        if pattern in url_lower:
            phishing_indicators += 3
    
    # Check 6: Subdomain spoofing
    trusted_domains = [
        'paypal', 'apple', 'microsoft', 'amazon',
        'google', 'facebook', 'netflix', 'bank'
    ]
    for domain in trusted_domains:
        if re.search(f'{domain}\\.com\\.[a-z]+', url_lower):
            phishing_indicators += 5
    
    # Check 7: No HTTPS for sensitive pages
    if ('login' in url_lower or 'secure' in url_lower or 
        'account' in url_lower or 'verify' in url_lower):
        if not url_lower.startswith('https'):
            phishing_indicators += 2
    
    # Check 8: Long URLs
    if len(url) > 100:
        phishing_indicators += 1
    
    return phishing_indicators >= 4

@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'models_ready': models_ready})

@app.route('/detect/url', methods=['POST'])
def detect_url():
    if not models_ready:
        return jsonify({'error': 'Run train_pipeline.py first'}), 503
    url = request.json.get('url')
    if not url:
        return jsonify({'error': 'URL required'}), 400
    try:
        result = detector.detect([url])[0]
        features = extractor.extract_all_features(url)
        zd = zero_day.detect(pd.DataFrame([features]))[0]
        
        # Smart rule-based detection
        is_phishing_by_rules = check_phishing_rules(url, features)
        
        if is_phishing_by_rules:
            result['is_phishing'] = True
            result['confidence'] = max(result['confidence'], 0.85)
            result['phishing_probability'] = 0.95
        
        return jsonify({
            'url': url,
            'is_phishing': result['is_phishing'],
            'confidence': round(result['confidence'], 3),
            'phishing_probability': round(
                result['phishing_probability'], 3),
            'zero_day_risk': zd['is_zero_day'],
            'anomaly_score': round(zd['anomaly_score'], 3)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/detect/batch', methods=['POST'])
def detect_batch():
    if not models_ready:
        return jsonify({'error': 'Run train_pipeline.py first'}), 503
    urls = request.json.get('urls', [])
    if not urls:
        return jsonify({'error': 'URLs list required'}), 400
    try:
        results = detector.detect(urls)
        output = []
        for u, r in zip(urls, results):
            features = extractor.extract_all_features(u)
            is_phishing_by_rules = check_phishing_rules(u, features)
            if is_phishing_by_rules:
                r['is_phishing'] = True
                r['confidence'] = max(r['confidence'], 0.85)
            output.append({
                'url': u,
                'is_phishing': r['is_phishing'],
                'confidence': round(r['confidence'], 3)})
        return jsonify({'results': output, 'total': len(output)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/analyze/sms', methods=['POST'])
def analyze_sms():
    if not models_ready:
        return jsonify({'error': 'Run train_pipeline.py first'}), 503
    text = request.json.get('text', '')
    if not text:
        return jsonify({'error': 'Text required'}), 400
    try:
        urls = re.findall(r'https?://[^\s]+|www\.[^\s]+', text)
        urls = ['http://'+u if not u.startswith('http')
                else u for u in urls]
        keywords = ['urgent','verify','account','suspended',
                    'login','confirm','security','update',
                    'unusual','blocked']
        keyword_hits = sum(
            1 for w in keywords if w in text.lower())
        url_results = []
        phishing_count = 0
        if urls:
            detections = detector.detect(urls)
            for url, r in zip(urls, detections):
                features = extractor.extract_all_features(url)
                is_phishing_by_rules = check_phishing_rules(url, features)
                if is_phishing_by_rules:
                    r['is_phishing'] = True
                    r['confidence'] = max(r['confidence'], 0.85)
                url_results.append({
                    'url': url,
                    'is_phishing': r['is_phishing'],
                    'confidence': round(r['confidence'], 3)})
                if r['is_phishing']:
                    phishing_count += 1
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
            'url_results': url_results,
            'recommendation': (
                'BLOCK' if risk == 'HIGH'
                else 'CAUTION' if risk == 'MEDIUM'
                else 'SAFE')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("\nAPI running")
    print("GET  /health")
    print("POST /detect/url")
    print("POST /detect/batch")
    print("POST /analyze/sms")
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)