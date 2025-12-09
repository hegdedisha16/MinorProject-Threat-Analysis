import streamlit as st
import requests
import socket
import whois
from datetime import datetime

# ---------------------------
# Helper Functions
# ---------------------------

def check_ssl(url):
    """Returns 1 if HTTPS is used, else 0."""
    return 1 if url.startswith("https://") else 0


def get_domain(url):
    """Extract domain from URL."""
    try:
        domain = url.split("//")[1].split("/")[0]
        return domain
    except:
        return None


def domain_age(domain):
    """Returns domain age in days."""
    try:
        w = whois.whois(domain)
        creation = w.creation_date

        if isinstance(creation, list):
            creation = creation[0]

        if creation is None:
            return 0

        today = datetime.now()
        age_days = (today - creation).days
        return age_days
    except:
        return 0


def check_ip_reputation(domain):
    """Basic IP check: private or suspicious IPs score higher risk."""
    try:
        ip = socket.gethostbyname(domain)

        # suspicious IP ranges
        if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168"):
            return 1
        
        return 0
    except:
        return 1


def check_red_flags(url):
    """Detect phishing-like patterns in URL."""
    score = 0

    if "-" in url:
        score += 1
    if len(url) > 75:
        score += 1
    if url.count(".") > 3:
        score += 1

    keywords = ["login", "verify", "secure", "bank", "account", "update"]
    if any(k in url.lower() for k in keywords):
        score += 1

    return score


def calculate_risk(url):
    """Main scoring logic."""
    if not url.startswith("http"):
        url = "https://" + url

    domain = get_domain(url)
    if not domain:
        return None, "Invalid URL"

    ssl_score = check_ssl(url)
    age = domain_age(domain)
    ip_score = check_ip_reputation(domain)
    flag_score = check_red_flags(url)

    # Risk score calculation
    risk_score = (
        (1 - ssl_score) * 20 +             # No HTTPS → more risk
        (1 if age < 180 else 0) * 20 +     # Domain younger than 6 months
        ip_score * 20 +                    # Suspicious IP
        flag_score * 10                    # URL red flags
    )

    risk_score = min(risk_score, 100)

    # Rating category
    if risk_score < 30:
        rating = "🟢 SAFE"
    elif risk_score < 70:
        rating = "🟡 SUSPICIOUS"
    else:
        rating = "🔴 HIGH RISK / POSSIBLY FRAUD"

    return risk_score, rating


# ---------------------------
# STREAMLIT APP UI
# ---------------------------

st.set_page_config(page_title="Threat Analysis Tool", page_icon="🛡️")

st.title("🛡️ Website Threat Analysis Tool")
st.write("Enter a website URL to determine its **risk score** and whether it may be fraudulent.")

url = st.text_input("Enter URL (example: google.com or https://example.com)")

if st.button("Analyze"):
    if url.strip() == "":
        st.error("Please enter a valid URL.")
    else:
        with st.spinner("Analyzing website…"):
            score, status = calculate_risk(url)

        if score is None:
            st.error(status)
        else:
            st.subheader("🔍 Analysis Result")
            st.metric("Risk Score", f"{score} / 100")
            st.write(f"**Status:** {status}")

            st.write("---")
            st.write("### 🔎 How the risk score is calculated:")
            st.write("""
            - No HTTPS → +20  
            - Domain age < 6 months → +20  
            - Suspicious IP → +20  
            - Phishing-like URL patterns → +10 each  
            """)

st.write("---")
st.write("⚙️ *Streamlit Threat Detection Demo App*")
