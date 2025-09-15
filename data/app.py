import streamlit as st

st.set_page_config(page_title="Cyber Threat Intelligence", layout="wide")
st.title("🔒 AI-Powered Cyber Threat Intelligence Platform")

# Sidebar role & theme
role = st.sidebar.selectbox("Select Role", ["Analyst", "Manager"])
theme = st.sidebar.radio("Select Theme", ["Light", "Dark"])

# Store in session state
st.session_state['role'] = role
st.session_state['theme'] = theme

# Page navigation
page = st.sidebar.selectbox("Navigate", ["Home", "Threat Analysis", "CVE Search", "Trends"])

if page == "Home":
    from pages import home
    home.show()
elif page == "Threat Analysis":
    from pages import threat_analysis
    threat_analysis.show()
elif page == "CVE Search":
    from pages import cve_search
    cve_search.show()
elif page == "Trends":
    from pages import trends
    trends.show()
