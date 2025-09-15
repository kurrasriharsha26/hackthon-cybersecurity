import streamlit as st
import pandas as pd
import io
from threat_analyzer import load_cve_data, preprocess_cve, prioritize_threats

def show():
    st.header("🔍 CVE Search")

    cve_items = load_cve_data()
    df = preprocess_cve(cve_items)
    df = prioritize_threats(df)

    if df.empty:
        st.info("No CVE data available.")
        return

    # Filters
    keyword = st.text_input("Keyword Search", placeholder="Type keyword here...")
    min_score, max_score = st.slider("Impact Score Range", 0.0, 10.0, (0.0, 10.0), 0.1)

    filtered = df[(df["Impact_Score"] >= min_score) & (df["Impact_Score"] <= max_score)]
    if keyword:
        filtered = filtered[filtered["Description"].str.contains(keyword, case=False, na=False)]

    # Role-based view
    role = st.session_state.get('role', 'Analyst')
    if role == "Analyst":
        st.subheader(f"Filtered CVEs ({len(filtered)})")
        st.dataframe(filtered)
    else:
        st.subheader(f"Top Filtered CVEs ({len(filtered)})")
        st.dataframe(filtered.sort_values("Priority_Score", ascending=False).head(5))

    # Download buttons
    if not filtered.empty:
        csv_data = filtered.to_csv(index=False)
        st.download_button("📥 Download CSV", data=csv_data, file_name="filtered_cves.csv", mime="text/csv")

        excel_buffer = io.BytesIO()
        with pd.ExcelWriter(excel_buffer, engine='xlsxwriter') as writer:
            filtered.to_excel(writer, index=False, sheet_name="Filtered CVEs")
        st.download_button("📥 Download Excel", data=excel_buffer, file_name="filtered_cves.xlsx",
                           mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
