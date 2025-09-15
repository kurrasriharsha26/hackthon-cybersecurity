import json
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MinMaxScaler

# -----------------------------
# Load CVE Data
# -----------------------------
def load_cve_data(filepath="data/cve_data.json"):
    """
    Load CVE data from JSON file.
    """
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"File not found: {filepath}")
        return []
    except json.JSONDecodeError:
        print(f"Invalid JSON format: {filepath}")
        return []

# -----------------------------
# Preprocess CVE Data
# -----------------------------
def preprocess_cve(cve_items):
    """
    Convert CVE JSON items into a DataFrame with necessary columns.
    """
    rows = []
    for item in cve_items:
        # Extract CVE ID
        cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "N/A")
        
        # Extract description
        description_list = item.get("cve", {}).get("description", {}).get("description_data", [])
        description = description_list[0].get("value", "") if description_list else ""

        # Extract impact score
        impact_score = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore", 0)

        rows.append({
            "CVE_ID": cve_id,
            "Description": description,
            "Impact_Score": impact_score
        })
    
    df = pd.DataFrame(rows)
    # Fill missing descriptions with placeholder
    df["Description"] = df["Description"].fillna("No description available").str.strip()
    return df

# -----------------------------
# Prioritize Threats
# -----------------------------
def prioritize_threats(df):
    """
    Calculate relevance and priority scores using TF-IDF and Impact Score.
    """
    # Drop rows with empty descriptions
    df = df[df["Description"].notna() & (df["Description"] != "")]
    
    if df.empty:
        print("No valid CVE descriptions to analyze.")
        df["Relevance_Score"] = 0
        df["Priority_Score"] = df["Impact_Score"]
        return df

    # TF-IDF scoring for relevance
    tfidf = TfidfVectorizer(stop_words="english")
    X = tfidf.fit_transform(df["Description"])
    relevance_score = X.sum(axis=1).A1  # sum of TF-IDF weights per CVE

    # Normalize relevance score between 0-1
    scaler = MinMaxScaler()
    df["Relevance_Score"] = scaler.fit_transform(relevance_score.reshape(-1, 1))

    # Calculate combined priority score
    df["Priority_Score"] = (df["Impact_Score"] + df["Relevance_Score"]) / 2

    # Sort by priority descending
    return df.sort_values(by="Priority_Score", ascending=False)

# -----------------------------
# Main Test
# -----------------------------
if __name__ == "__main__":
    cve_items = load_cve_data()
    df = preprocess_cve(cve_items)
    df = prioritize_threats(df)
    print(df.head(10))
