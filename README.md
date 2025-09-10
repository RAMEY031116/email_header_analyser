# email_header_analyser

# Dim Sum 🥟 Email Header Analyzer

**Author:** Bipzilla  

Analyze `.msg` and `.eml` email files to inspect headers, verify authentication results (SPF, DKIM, DMARC), and determine legitimacy. This tool is useful for email forensics and investigation.

---

## Features

- Upload multiple `.msg` or `.eml` files.
- View full email headers.
- Extract and display:
  - `From`, `To`, `Cc`, `Bcc`
  - `Subject` and `Date`
  - `Message-ID` and submit time
- Check email authentication:
  - SPF
  - DKIM
  - DMARC
- Legitimacy analysis:  
  - Likely Legitimate  
  - Possibly Legitimate (exported copy / incomplete headers)  
  - Possibly Fake / Draft  
- Download analysis results as `.txt`.
- Web interface built with Streamlit for easy access anywhere.

---

## Screenshot

![Dim Sum Email Header Analyzer Screenshot](screenshot.png)

---

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/dimsum-email-analyzer.git
cd dimsum-email-analyzer
