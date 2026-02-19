import pandas as pd
import random
import os

os.makedirs('datasets', exist_ok=True)

print("Generating legitimate URLs...")
legit_domains = [
    'google.com','facebook.com','amazon.com','microsoft.com',
    'apple.com','netflix.com','linkedin.com','github.com',
    'stackoverflow.com','wikipedia.org','yahoo.com','twitter.com'
]
legit_paths = ['/','home','/about','/products',
               '/help','/support','/account']

legitimate_urls = []
for i in range(5000):
    domain = random.choice(legit_domains)
    path = random.choice(legit_paths)
    protocol = 'https' if random.random() > 0.2 else 'http'
    legitimate_urls.append(
        f"{protocol}://www.{domain}{path}?id={i}")

print("Generating phishing URLs...")
phishing_bases = [
    'paypal.com.security-verify.com','apple-id-verify.net',
    'bankofamerica-update.com','amazon-prime-renewal.net',
    'microsoft-365-verify.org','dhl-parcel-delivery.info',
    'netflix-account-suspended.net','instagram-verify-badge.com',
    'secure-account-verify.net','login-verify-update.com',
    'account-suspended-verify.net','banking-secure-portal.com'
]
phishing_paths = [
    'login','verify','account','update',
    'security','confirm','signin'
]

phishing_urls = []
for i in range(5000):
    base = random.choice(phishing_bases)
    path = random.choice(phishing_paths)
    phishing_urls.append(
        f"http://{base}/{path}"
        f"?id={i}&token={random.randint(100000,999999)}")

data = []
for url in legitimate_urls:
    data.append({'url': url, 'label': 0})
for url in phishing_urls:
    data.append({'url': url, 'label': 1})

df = pd.DataFrame(data).sample(frac=1).reset_index(drop=True)
df.to_csv('datasets/phishing_dataset.csv', index=False)

train_size = int(0.8 * len(df))
df[:train_size].to_csv('datasets/train_dataset.csv', index=False)
df[train_size:].to_csv('datasets/test_dataset.csv', index=False)

print(f"Done! Total: {len(df)} URLs")
print(f"Legitimate: {len(legitimate_urls)}")
print(f"Phishing: {len(phishing_urls)}")
print("Saved in datasets/ folder")