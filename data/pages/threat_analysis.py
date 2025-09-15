import streamlit as st
import plotly.express as px
from threat_analyzer import load_cve_data, preprocess_cve, prioritize_threats

def show():
    st.header("📊 Threat Analysis")

    cve_items = load_cve_data()
    df = preprocess_cve(cve_items)
    df = prioritize_threats(df)
    
    if df.empty:
        st.info("No CVE data available.")
        return

    # Theme
    theme = st.session_state.get('theme', 'Light')
    bg_color = "#111111" if theme == "Dark" else "#FFFFFF"
    color_scale = "reds" if theme == "Dark" else "Reds"

    # Top CVEs
    st.subheader("Top 10 CVEs by Priority Score")
    st.dataframe(df.head(10))

    # Impact Score Histogram
    fig = px.histogram(df, x="Impact_Score", nbins=10, title="Impact Score Distribution")
    fig.update_layout(paper_bgcolor=bg_color, plot_bgcolor=bg_color)
    st.plotly_chart(fig, use_container_width=True)

    # Top 10 Priority Score Bar Chart
    fig2 = px.bar(df.head(10), x="CVE_ID", y="Priority_Score",
                  color="Priority_Score", color_continuous_scale=color_scale)
    fig2.update_layout(paper_bgcolor=bg_color, plot_bgcolor=bg_color)
    st.plotly_chart(fig2, use_container_width=True)

    # Simulated Threat Mitigation
    st.subheader("Simulate Threat Mitigation")
    top_cve = df.head(1).copy()
    st.write(f"Top CVE: {top_cve['CVE_ID'].values[0]} - Priority Score: {top_cve['Priority_Score'].values[0]:.2f}")
    mitigate = st.slider("Mitigation Effectiveness (%)", 0, 100, 0)
    simulated_score = top_cve["Priority_Score"].values[0] * (1 - mitigate / 100)
    st.metric("Simulated Priority Score after Mitigation", f"{simulated_score:.2f}")
