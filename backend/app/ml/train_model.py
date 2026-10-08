import os
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score, accuracy_score
from xgboost import XGBClassifier
from backend.app.ml.feature_extractor import extract_url_features

# Curated balanced dataset of phishing and benign URLs
DATASET = [
    # Benign URLs (label: 0)
    ("https://www.google.com", 0),
    ("https://github.com/login", 0),
    ("https://stackoverflow.com/questions", 0),
    ("https://www.wikipedia.org/wiki/Main_Page", 0),
    ("https://www.amazon.com/gp/help/customer/display.html", 0),
    ("https://www.microsoft.com/en-us/", 0),
    ("https://www.apple.com/iphone/", 0),
    ("https://www.netflix.com/browse", 0),
    ("https://www.linkedin.com/feed/", 0),
    ("https://www.reddit.com/r/python/", 0),
    ("https://www.yahoo.com", 0),
    ("https://twitter.com/explore", 0),
    ("https://www.instagram.com", 0),
    ("https://www.dropbox.com/login", 0),
    ("https://cloudflare.com/learning/", 0),
    ("https://www.python.org/downloads/", 0),
    ("https://pypi.org/project/xgboost/", 0),
    ("https://fastapi.tiangolo.com/", 0),
    ("https://www.postgresql.org/docs/", 0),
    ("https://supabase.com/docs", 0),
    ("https://www.bbc.com/news", 0),
    ("https://edition.cnn.com", 0),
    ("https://www.nytimes.com", 0),
    ("https://www.spotify.com", 0),
    ("https://www.adobe.com", 0),
    ("https://www.salesforce.com", 0),
    ("https://www.zoom.us", 0),
    ("https://slack.com", 0),
    ("https://notion.so", 0),
    ("https://trello.com", 0),

    # Phishing URLs (label: 1)
    ("http://login.secure-apple-id.com.xyz/account/signin", 1),
    ("http://paypal-update-security-alert.top/webapps/login", 1),
    ("http://192.168.1.100/netbanking/login.php", 1),
    ("http://netflix-account-suspended-verify.gq/login", 1),
    ("http://free-nitro-discord.tk/claim", 1),
    ("http://amazon-prime-reward-win.ml/verify", 1),
    ("http://microsoft-security-alert-911.cf/support", 1),
    ("http://steam-community-giveaway.su/login", 1),
    ("http://bankofamerica-secure-login.buzz/auth", 1),
    ("http://chase-online-banking-update.icu/signin", 1),
    ("http://wellsfargo-security-check.site/verify", 1),
    ("http://citigroup-client-portal.online/login", 1),
    ("http://instagram-blue-badge-verify.loan/claim", 1),
    ("http://facebook-security-update.club/login", 1),
    ("http://whatsapp-web-login-qr.click/auth", 1),
    ("http://crypto-airdrop-bonus.link/claim", 1),
    ("http://binance-secure-wallet-login.work/auth", 1),
    ("http://metamask-recovery-seed.party/import", 1),
    ("http://coinbase-account-lock.ml/verify", 1),
    ("http://apple-support-billing.gq/update", 1),
    ("http://google-drive-shared-doc.tk/auth", 1),
    ("http://dropbox-file-transfer.cf/download", 1),
    ("http://linkedin-job-offer-review.su/login", 1),
    ("http://telegram-web-login.buzz/auth", 1),
    ("http://spotify-premium-free.icu/claim", 1),
    ("http://adobe-invoice-view.site/document", 1),
    ("http://docusign-document-sign.online/verify", 1),
    ("http://fedex-package-tracking.loan/delivery", 1),
    ("http://dhl-express-shipment.club/track", 1),
    ("http://usps-delivery-status.click/update", 1)
]

def build_dataset():
    features_list = []
    labels = []
    for url, label in DATASET:
        feats = extract_url_features(url)
        features_list.append(feats)
        labels.append(label)
    df = pd.DataFrame(features_list)
    y = np.array(labels)
    return df, y

def main():
    print("Building dataset from curated samples...")
    X, y = build_dataset()
    print(f"Dataset shape: {X.shape}, Labels shape: {y.shape}")
    print(f"Class distribution: Benign={np.sum(y == 0)}, Phishing={np.sum(y == 1)}")

    # Split into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    print(f"Training set size: {len(X_train)}, Test set size: {len(X_test)}")

    # Initialize and train XGBoost Classifier
    model = XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        random_state=42,
        eval_metric='logloss'
    )
    
    model.fit(X_train, y_train)

    # Predictions
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    # Evaluation metrics
    acc = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_test, y_proba)

    print("\n--- Model Evaluation Metrics ---")
    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"ROC-AUC:   {roc_auc:.4f}")

    # Save model artifact
    output_dir = os.path.dirname(__file__)
    model_path = os.path.join(output_dir, "phishing_xgb_v1.pkl")
    joblib.dump(model, model_path)
    print(f"\nModel artifact successfully saved to: {model_path}")

if __name__ == "__main__":
    main()
