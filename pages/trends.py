import streamlit as st
import pandas as pd
import plotly.express as px
from threat_analyzer import load_cve_data, preprocess_cve, prioritize_threats

def show():
    st.header("📈 CVE Trends Over Time")

    cve_items = load_cve_data()
    df = preprocess_cve(cve_items)
    df = prioritize_threats(df)

    if df.empty:
        st.info("No CVE data available.")
        return

    # Dummy discovery dates for visualization
    df["Discovery_Date"] = pd.date_range(end=pd.Timestamp.today(), periods=len(df))

    theme = st.session_state.get('theme', 'Light')
    bg_color = "#111111" if theme == "Dark" else "#FFFFFF"
    
    # CVE Count Over Time
    st.subheader("CVE Count Over Time")
    count_df = df.groupby(df["Discovery_Date"].dt.date).size().reset_index(name="Count")
    fig = px.line(count_df, x="Discovery_Date", y="Count", title="CVE Count Over Time")
    fig.update_layout(paper_bgcolor=bg_color, plot_bgcolor=bg_color)
    st.plotly_chart(fig, use_container_width=True)

    # Average Impact Score Over Time
    st.subheader("Average Impact Score Over Time")
    avg_df = df.groupby(df["Discovery_Date"].dt.date)["Impact_Score"].mean().reset_index()
    fig2 = px.line(avg_df, x="Discovery_Date", y="Impact_Score", title="Impact Score Trend")
    fig2.update_layout(paper_bgcolor=bg_color, plot_bgcolor=bg_color)
    st.plotly_chart(fig2, use_container_width=True)
