import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from sklearn.preprocessing import StandardScaler
import sys, os
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from preprocessing.feature_extractor import URLFeatureExtractor

device = torch.device('cpu')

class EmbeddingNetwork(nn.Module):
    def __init__(self, input_dim):
        super(EmbeddingNetwork, self).__init__()
        self.network = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.BatchNorm1d(128),
            nn.Dropout(0.3),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.BatchNorm1d(64),
            nn.Dropout(0.3),
            nn.Linear(64, 32)
        )

    def forward(self, x):
        return self.network(x)

class PrototypicalNetwork:
    def __init__(self, input_dim):
        self.model = EmbeddingNetwork(input_dim).to(device)
        self.optimizer = optim.Adam(
            self.model.parameters(), lr=0.001)
        self.criterion = nn.CrossEntropyLoss()

    def compute_prototypes(self, support_emb, support_labels, n_way):
        prototypes = []
        for i in range(n_way):
            mask = support_labels == i
            class_emb = support_emb[mask]
            prototypes.append(class_emb.mean(dim=0))
        return torch.stack(prototypes)

    def compute_distances(self, queries, prototypes):
        q = queries.unsqueeze(1)
        p = prototypes.unsqueeze(0)
        return torch.sum((q - p) ** 2, dim=2)

    def train_episode(self, support_set, support_labels,
                      query_set, query_labels):
        self.model.train()
        support_t = torch.FloatTensor(support_set).to(device)
        support_l = torch.LongTensor(support_labels).to(device)
        query_t = torch.FloatTensor(query_set).to(device)
        query_l = torch.LongTensor(query_labels).to(device)

        self.optimizer.zero_grad()
        support_emb = self.model(support_t)
        query_emb = self.model(query_t)

        n_way = len(torch.unique(support_l))
        prototypes = self.compute_prototypes(
            support_emb, support_l, n_way)
        distances = self.compute_distances(query_emb, prototypes)

        loss = self.criterion(-distances, query_l)
        loss.backward()
        self.optimizer.step()

        preds = torch.argmax(-distances, dim=1)
        acc = (preds == query_l).float().mean().item()
        return loss.item(), acc

    def predict(self, support_set, support_labels, query_set):
        self.model.eval()
        with torch.no_grad():
            support_t = torch.FloatTensor(support_set).to(device)
            support_l = torch.LongTensor(support_labels).to(device)
            query_t = torch.FloatTensor(query_set).to(device)

            support_emb = self.model(support_t)
            query_emb = self.model(query_t)

            n_way = len(torch.unique(support_l))
            prototypes = self.compute_prototypes(
                support_emb, support_l, n_way)
            distances = self.compute_distances(query_emb, prototypes)

            predictions = torch.argmax(-distances, dim=1).numpy()
            probabilities = torch.softmax(-distances, dim=1).numpy()
        return predictions, probabilities

class PhishingDetector:
    def __init__(self):
        self.feature_extractor = URLFeatureExtractor()
        self.network = None
        self.scaler = StandardScaler()
        self.support_urls = []
        self.support_labels = []
        self.is_trained = False

    def prepare_features(self, urls):
        features = self.feature_extractor.create_feature_vector(urls)
        return features.values.astype(float)

    def create_episode(self, X, y, k_shot=5, n_query=5):
        support_set, support_labels = [], []
        query_set, query_labels = [], []
        for i in range(2):
            indices = np.where(y == i)[0]
            selected = np.random.choice(
                indices, k_shot + n_query, replace=False)
            support_set.extend(X[selected[:k_shot]])
            support_labels.extend([i] * k_shot)
            query_set.extend(X[selected[k_shot:]])
            query_labels.extend([i] * n_query)
        return (np.array(support_set), np.array(support_labels),
                np.array(query_set), np.array(query_labels))

    def train(self, train_urls, train_labels, n_epochs=50):
        print("Extracting features...")
        X = self.prepare_features(train_urls)
        X = self.scaler.fit_transform(X)
        y = np.array(train_labels)
        print(f"Building network (input_dim={X.shape[1]})...")
        self.network = PrototypicalNetwork(X.shape[1])
        print(f"Training {n_epochs} episodes...")
        for epoch in range(n_epochs):
            support_set, support_labels, query_set, query_labels = \
                self.create_episode(X, y)
            loss, acc = self.network.train_episode(
                support_set, support_labels,
                query_set, query_labels)
            if (epoch + 1) % 10 == 0:
                print(f"  Episode {epoch+1}/{n_epochs} "
                      f"Loss:{loss:.4f} Acc:{acc:.4f}")
        self.is_trained = True
        print("Training complete!")

    def detect(self, urls):
        if not self.is_trained:
            raise ValueError("Train the model first!")
        all_urls = self.support_urls + list(urls)
        X_all = self.prepare_features(all_urls)
        X_all = self.scaler.transform(X_all)
        support_X = X_all[:len(self.support_urls)]
        query_X = X_all[len(self.support_urls):]
        predictions, probabilities = self.network.predict(
            support_X, np.array(self.support_labels), query_X)
        results = []
        for pred, prob in zip(predictions, probabilities):
            results.append({
                'is_phishing': bool(pred),
                'confidence': float(np.max(prob)),
                'phishing_probability': float(prob[1])
                    if len(prob) > 1 else 0.5
            })
        return results