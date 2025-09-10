# dim_sum_app.py
import streamlit as st
import extract_msg
import email
from email import policy
import re

st.set_page_config(
    page_title="Dim Sum 🥟 Email Header Analyzer",
    layout="wide"
)

st.title("Dim Sum 🥟 Email Header Analyzer")
st.markdown("Author: **Bipzilla** | Upload .msg or .eml files to analyze headers and legitimacy")

# --- File uploader ---
uploaded_files = st.file_uploader(
    "Upload .msg or .eml files",
    type=["msg", "eml"],
    accept_multiple_files=True
)

# --- Helper functions ---
def extract_auth_results(raw_headers):
    results = {}
    spf_match = re.search(r'SPF[:=]\s*([^\s;]+)', raw_headers, re.IGNORECASE)
    results['SPF'] = spf_match.group(1) if spf_match else 'Not Found'

    dkim_match = re.search(r'DKIM-Signature:.*', raw_headers, re.IGNORECASE)
    results['DKIM'] = 'Present' if dkim_match else 'Not Found'

    dmarc_match = re.search(r'dmarc=([^\s;]+)', raw_headers, re.IGNORECASE)
    results['DMARC'] = dmarc_match.group(1) if dmarc_match else 'Not Found'

    return results

def check_legitimacy(raw_headers, auth_results):
    headers_lower = {k.lower(): v for k, v in raw_headers.items()}
    received = headers_lower.get('received', None)
    msg_id = headers_lower.get('message-id', None)

    reasons = []
    if received:
        result = "✅ Likely Legitimate"
    elif msg_id:
        result = "⚠️ Possibly Legitimate (exported web copy / incomplete headers)"
        reasons.append("No Received headers found, but Message-ID exists")
    else:
        result = "❌ Possibly Fake / Draft"
        reasons.append("No Received headers found")
        reasons.append("No Message-ID found")

    if auth_results.get('SPF') == 'Not Found':
        reasons.append("No SPF record / check missing")
    if auth_results.get('DKIM') == 'Not Found':
        reasons.append("No DKIM signature")
    if auth_results.get('DMARC') == 'Not Found':
        reasons.append("No DMARC record / check missing")

    return result, reasons

def analyze_msg(file):
    msg = extract_msg.Message(file)
    raw_headers = msg.header
    submit_time = msg.date
    return raw_headers, submit_time

def analyze_eml(file):
    msg = email.message_from_bytes(file.read(), policy=policy.default)
    raw_headers = dict(msg.items())
    submit_time = msg['Date']
    return raw_headers, submit_time

# --- Process uploaded files ---
if uploaded_files:
    for uploaded_file in uploaded_files:
        st.markdown(f"### File: {uploaded_file.name}")
        try:
            if uploaded_file.name.lower().endswith('.msg'):
                raw_headers, submit_time = analyze_msg(uploaded_file)
            else:
                raw_headers, submit_time = analyze_eml(uploaded_file)

            # Full headers
            st.subheader("All Headers")
            for k, v in raw_headers.items():
                st.text(f"{k}: {v}")

            # Key info
            st.subheader("Key Email Info")
            st.text(f"From: {raw_headers.get('From', 'N/A')}")
            st.text(f"To: {raw_headers.get('To', 'N/A')}")
            st.text(f"Cc: {raw_headers.get('Cc', 'N/A')}")
            st.text(f"Bcc: {raw_headers.get('Bcc', 'N/A')}")
            st.text(f"Subject: {raw_headers.get('Subject', 'N/A')}")
            st.text(f"Date: {raw_headers.get('Date', 'N/A')}")
            headers_lower = {k.lower(): v for k, v in raw_headers.items()}
            message_id = headers_lower.get('message-id', 'N/A')
            st.text(f"Message-ID: {message_id}")
            if submit_time:
                st.text(f"PR_CLIENT_SUBMIT_TIME / Submit Time: {submit_time}")

            # Authentication
            raw_headers_str = "\n".join([f"{k}: {v}" for k, v in raw_headers.items()])
            auth_results = extract_auth_results(raw_headers_str)
            st.subheader("Authentication / Security Info")
            st.text(f"SPF: {auth_results.get('SPF')}")
            st.text(f"DKIM: {auth_results.get('DKIM')}")
            st.text(f"DMARC: {auth_results.get('DMARC')}")

            # Legitimacy
            result, reasons = check_legitimacy(raw_headers, auth_results)
            st.subheader("Email Legitimacy Check")
            st.text(f"Result: {result}")
            if reasons:
                st.text(f"Reason(s): {', '.join(reasons)}")
            else:
                st.text("All key criteria present.")

        except Exception as e:
            st.error(f"Error processing file: {e}")
