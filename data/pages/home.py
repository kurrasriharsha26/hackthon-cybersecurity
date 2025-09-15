import streamlit as st
from threat_analyzer import load_cve_data, preprocess_cve, prioritize_threats

def show():
    st.header("🏠 Home - CVE Summary")

    cve_items = load_cve_data()
    df = preprocess_cve(cve_items)
    df = prioritize_threats(df)

    if df.empty:
        st.info("No CVE data available. Click 'Fetch Latest CVEs'.")
        return

    # Summary metrics
    st.subheader("Summary Metrics")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total CVEs", len(df))
    col2.metric("Max Impact Score", df["Impact_Score"].max())
    col3.metric("Avg Priority Score", round(df["Priority_Score"].mean(), 2))

    # Role-based view
    role = st.session_state.get('role', 'Analyst')
    if role == "Analyst":
        st.subheader("Top 5 CVEs")
        st.dataframe(df.head(5))
    else:
        st.subheader("Top 3 Critical CVEs")
        st.dataframe(df.sort_values("Priority_Score", ascending=False).head(3))
