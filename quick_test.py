import requests

print("Testing Batch URLs...")
print("="*60)

urls = [
    "http://paypal.com.security-verify.com/login",
    "https://www.google.com",
    "http://bankofamerica-update.com/verify",
    "https://github.com",
    "http://apple-id-verify.net/account"
]

r = requests.post(
    'http://localhost:5000/detect/batch',
    json={'urls': urls}
)

results = r.json()

for item in results['results']:
    status = "🚨 PHISHING" if item['is_phishing'] else "✅ SAFE"
    print(f"{status:15} {item['url'][:45]}")

print("="*60)