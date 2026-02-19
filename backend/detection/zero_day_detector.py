import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

class ZeroDayDetector:
    def __init__(self):
        self.iso_forest = IsolationForest(
            contamination=0.1, random_state=42,
            n_estimators=100)
        self.lof = LocalOutlierFactor(
            contamination=0.1, novelty=True)
        self.fitted = False

    def get_features(self, df):
        cols = ['url_length','digit_ratio','entropy',
                'subdomain_count','suspicious_words_count',
                'parameter_count','count_slash','count_dots']
        available = [c for c in cols if c in df.columns]
        return df[available].fillna(0).values

    def fit(self, legit_features_df):
        X = self.get_features(legit_features_df)
        self.iso_forest.fit(X)
        self.lof.fit(X)
        self.fitted = True
        print(f"Zero-day detector trained on {len(X)} URLs")

    def detect(self, features_df):
        if not self.fitted:
            raise ValueError("Fit the detector first!")
        X = self.get_features(features_df)
        if_scores = self.iso_forest.decision_function(X)
        lof_scores = self.lof.decision_function(X)
        combined = (if_scores + lof_scores) / 2
        results = []
        for score in combined:
            results.append({
                'is_zero_day': bool(score < -0.3),
                'anomaly_score': float(score)
            })
        return results