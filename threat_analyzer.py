import json
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MinMaxScaler
import os

DATA_FILE = "data/cve_data.json"

def load_cve_data(filepath=DATA_FILE):
    """Load CVE JSON data"""
    if os.path.exists(filepath):
        with open(filepath) as f:
            return json.load(f)
    else:
        return []

def preprocess_cve(cve_items):
    """Convert raw CVE JSON into DataFrame"""
    rows = []
    for item in cve_items:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "N/A")
        descs = cve.get("descriptions", [])
        description = descs[0].get("value", "") if descs else ""
        metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
        impact_score = metrics[0].get("cvssData", {}).get("baseScore", 0) if metrics else 0

        rows.append({
            "CVE_ID": cve_id,
            "Description": description,
            "Impact_Score": impact_score
        })
    return pd.DataFrame(rows)

def prioritize_threats(df):
    """Calculate relevance and priority score"""
    if df.empty or "Description" not in df.columns:
        return df

    tfidf = TfidfVectorizer(stop_words="english")
    X = tfidf.fit_transform(df["Description"].fillna(""))
    relevance_score = X.sum(axis=1).A1

    scaler = MinMaxScaler()
    df["Relevance_Score"] = scaler.fit_transform(relevance_score.reshape(-1,1))
    df["Priority_Score"] = (df["Impact_Score"] + df["Relevance_Score"]) / 2

    return df.sort_values(by="Priority_Score", ascending=False)
