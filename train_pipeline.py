import pandas as pd
import numpy as np
import joblib
import os, sys

sys.path.append(
    os.path.join(os.path.dirname(__file__), 'backend'))
from models.prototypical_network import PhishingDetector
from detection.zero_day_detector import ZeroDayDetector
from preprocessing.feature_extractor import URLFeatureExtractor

print("="*60)
print("PHISHING DETECTION - TRAINING PIPELINE")
print("="*60)

print("\n[1/6] Loading dataset...")
df = pd.read_csv('datasets/phishing_dataset.csv')
train_df = pd.read_csv('datasets/train_dataset.csv')
test_df = pd.read_csv('datasets/test_dataset.csv')
print(f"  Total:{len(df)} Train:{len(train_df)} Test:{len(test_df)}")

print("\n[2/6] Training model...")
detector = PhishingDetector()
detector.train(
    train_df['url'].tolist(),
    train_df['label'].values,
    n_epochs=50)

print("\n[3/6] Creating support set...")
p_sample = train_df[train_df['label']==1].sample(30)
l_sample = train_df[train_df['label']==0].sample(30)
support_df = pd.concat([p_sample, l_sample])
detector.support_urls = support_df['url'].tolist()
detector.support_labels = support_df['label'].tolist()
print(f"  Support set: {len(detector.support_urls)} examples")

print("\n[4/6] Training zero-day detector...")
extractor = URLFeatureExtractor()
legit_urls = train_df[train_df['label']==0]['url'].tolist()
legit_features = extractor.create_feature_vector(legit_urls)
zero_day = ZeroDayDetector()
zero_day.fit(legit_features)

print("\n[5/6] Evaluating...")
test_sample = test_df.sample(min(50, len(test_df)))
correct = 0
for _, row in test_sample.iterrows():
    result = detector.detect([row['url']])[0]
    if result['is_phishing'] == bool(row['label']):
        correct += 1
accuracy = correct / len(test_sample)
print(f"  Accuracy: {accuracy:.1%}")

print("\n[6/6] Saving models...")
os.makedirs('models_saved', exist_ok=True)
joblib.dump(detector, 'models_saved/detector.pkl')
joblib.dump(zero_day, 'models_saved/zero_day.pkl')
support_df.to_csv('models_saved/support_set.csv', index=False)
print("  Saved!")

print("\n" + "="*60)
print(f"DONE! Accuracy: {accuracy:.1%}")
print("="*60)
print("Next: python backend/api/app.py")