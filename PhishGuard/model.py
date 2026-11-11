import os
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report

# Expected training file: archive/phishing_site_urls.csv with URL + Label columns.
DATA_PATH = "archive/phishing_site_urls.csv"
if not os.path.exists(DATA_PATH):
    raise FileNotFoundError(
        f"Training dataset not found: {DATA_PATH}\n"
        "The runtime app can still use the supplied url_model.pkl. "
        "Put a URL dataset with columns URL and Label in archive/ before retraining."
    )

data = pd.read_csv(DATA_PATH)
data = data.dropna(subset=["URL", "Label"])
X_text = data["URL"].astype(str).str.lower()
y = data["Label"].astype(str).str.lower()

# Character n-grams are much better suited to URLs than ordinary word tokens:
# they can learn patterns such as misspellings, punctuation and hostname fragments.
vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(3, 5),
    min_df=2,
    sublinear_tf=True,
    max_features=300000
)
X = vectorizer.fit_transform(X_text)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

model = LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred) * 100)
print(classification_report(y_test, y_pred))

joblib.dump(model, "url_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")
print("Model and vectorizer saved successfully.")
