# dim_sum_app.py
import streamlit as st
import extract_msg
import email
from email import policy
import re
import json
import traceback

st.set_page_config(
    page_title="Dim Sum 🥟 Email Header Analyzer",
    layout="wide"
)

st.title("Dim Sum 🥟 Email Header Analyzer")
st.markdown("Author: **Bipzilla** | Upload .msg or .eml files to analyze headers and legitimacy")

# --- File uploader ---
uploaded_files = st.file_uploader(
    "Upload .msg or .eml files (Max size: 5MB each)",
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
        color = "green"
    elif msg_id:
        result = "⚠️ Possibly Legitimate (exported web copy / incomplete headers)"
        reasons.append("No Received headers found, but Message-ID exists")
        color = "orange"
    else:
        result = "❌ Possibly Fake / Draft"
        reasons.append("No Received headers found")
        reasons.append("No Message-ID found")
        color = "red"

    if auth_results.get('SPF') == 'Not Found':
        reasons.append("No SPF record / check missing")
    if auth_results.get('DKIM') == 'Not Found':
        reasons.append("No DKIM signature")
    if auth_results.get('DMARC') == 'Not Found':
        reasons.append("No DMARC record / check missing")

    return result, reasons, color

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
        if uploaded_file.size > 5 * 1024 * 1024:
            st.warning("File too large (>5MB). Skipping.")
            continue
        try:
            if uploaded_file.name.lower().endswith('.msg'):
                raw_headers, submit_time = analyze_msg(uploaded_file)
                raw_headers_dict = dict(line.split(":", 1) for line in raw_headers.splitlines() if ":" in line)
            else:
                raw_headers_dict, submit_time = analyze_eml(uploaded_file)

            # Full headers
            with st.expander("📬 All Headers"):
                for k, v in raw_headers_dict.items():
                    st.text(f"{k}: {v}")

            # Key info
            st.subheader("📌 Key Email Info")
            st.text(f"From: {raw_headers_dict.get('From', 'N/A')}")
            st.text(f"To: {raw_headers_dict.get('To', 'N/A')}")
            st.text(f"Cc: {raw_headers_dict.get('Cc', 'N/A')}")
            st.text(f"Bcc: {raw_headers_dict.get('Bcc', 'N/A')}")
            st.text(f"Subject: {raw_headers_dict.get('Subject', 'N/A')}")
            st.text(f"Date: {raw_headers_dict.get('Date', 'N/A')}")
            headers_lower = {k.lower(): v for k, v in raw_headers_dict.items()}
            message_id = headers_lower.get('message-id', 'N/A')
            st.text(f"Message-ID: {message_id}")
            if submit_time:
                st.text(f"PR_CLIENT_SUBMIT_TIME / Submit Time: {submit_time}")

            # Authentication
            raw_headers_str = "\n".join([f"{k}: {v}" for k, v in raw_headers_dict.items()])
            auth_results = extract_auth_results(raw_headers_str)
            st.subheader("🔐 Authentication / Security Info")
            st.text(f"SPF: {auth_results.get('SPF')}")
            st.text(f"DKIM: {auth_results.get('DKIM')}")
            st.text(f"DMARC: {auth_results.get('DMARC')}")

            # Legitimacy
            result, reasons, color = check_legitimacy(raw_headers_dict, auth_results)
            st.subheader("🕵️ Email Legitimacy Check")
            st.markdown(f"<span style='color:{color}; font-weight:bold;'>Result: {result}</span>", unsafe_allow_html=True)
            if reasons:
                st.markdown(f"**Reason(s):** {', '.join(reasons)}")
            else:
                st.text("All key criteria present.")

            # Download parsed results
            parsed_data = {
                "File": uploaded_file.name,
                "From": raw_headers_dict.get('From', 'N/A'),
                "To": raw_headers_dict.get('To', 'N/A'),
                "Subject": raw_headers_dict.get('Subject', 'N/A'),
                "Date": raw_headers_dict.get('Date', 'N/A'),
                "Message-ID": message_id,
                "Submit Time": submit_time,
                "SPF": auth_results.get('SPF'),
                "DKIM": auth_results.get('DKIM'),
                "DMARC": auth_results.get('DMARC'),
                "Legitimacy Result": result,
                "Reasons": reasons
            }
            json_str = json.dumps(parsed_data, indent=2)
            st.download_button("📥 Download Analysis as JSON", data=json_str, file_name=f"{uploaded_file.name}_analysis.json", mime="application/json")

        except Exception as e:
            st.error("Error processing file. Please check the format or try another file.")
            st.text("Debug Info:")
            st.text(traceback.format_exc())
