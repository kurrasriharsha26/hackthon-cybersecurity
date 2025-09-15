def prioritize_threats(df):
    """
    Calculate relevance and priority scores using TF-IDF and Impact Score.
    Handles empty descriptions safely.
    """
    # Fill missing descriptions
    df["Description"] = df["Description"].fillna("").str.strip()

    # Filter out empty descriptions
    valid_df = df[df["Description"] != ""].copy()

    if valid_df.empty:
        # No valid text for TF-IDF
        df["Relevance_Score"] = 0
        df["Priority_Score"] = df["Impact_Score"]  # just use impact score
        print("Warning: No valid CVE descriptions available for TF-IDF scoring.")
        return df

    # TF-IDF scoring
    tfidf = TfidfVectorizer(stop_words="english", min_df=1)
    try:
        X = tfidf.fit_transform(valid_df["Description"])
    except ValueError:
        # TF-IDF failed due to all stopwords
        valid_df["Relevance_Score"] = 0
    else:
        relevance_score = X.sum(axis=1).A1  # sum TF-IDF weights
        # Normalize
        from sklearn.preprocessing import MinMaxScaler
        scaler = MinMaxScaler()
        valid_df["Relevance_Score"] = scaler.fit_transform(relevance_score.reshape(-1, 1))

    # Calculate Priority Score
    valid_df["Priority_Score"] = (valid_df["Impact_Score"] + valid_df["Relevance_Score"]) / 2

    # Merge back with any rows that were filtered out (empty descriptions)
    df = df.merge(
        valid_df[["CVE_ID", "Relevance_Score", "Priority_Score"]],
        on="CVE_ID",
        how="left"
    )

    # Fill NaNs for rows with no descriptions
    df["Relevance_Score"] = df["Relevance_Score"].fillna(0)
    df["Priority_Score"] = df["Priority_Score"].fillna(df["Impact_Score"])

    # Sort by priority
    return df.sort_values(by="Priority_Score", ascending=False)
