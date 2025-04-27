import os
import zipfile
import string
import re
import base64
import pandas as pd
import streamlit as st

# === Config ===
MAX_FILE_SIZE_MB = 10
MAX_LINE_LENGTH = 10000
SUSPICIOUS_RATIO_THRESHOLD = 0.05

# === Cell-level checks ===
def is_potentially_malicious(cell_value):
    if not isinstance(cell_value, str):
        return False

    # Dangerous formula triggers
    if cell_value.strip().startswith(('=', '+', '-', '@')):
        return True

    # Base64 detection
    base64_regex = r'^[A-Za-z0-9+/=]{20,}$'
    if re.match(base64_regex, cell_value.strip()):
        try:
            decoded = base64.b64decode(cell_value.strip(), validate=True)
            if b'MZ' in decoded or b'<?xml' in decoded:
                return True
        except Exception:
            pass

    # Script/payload keywords
    if any(keyword in cell_value.lower() for keyword in ['powershell', 'cmd', 'wget', 'curl', '<script', 'onerror']):
        return True

    return False

# === CSV Classifier ===
def classify_csv(file_path):
    # File size check
    if os.path.getsize(file_path) > MAX_FILE_SIZE_MB * 1024 * 1024:
        return "❌ File too large"

    try:
        df = pd.read_csv(file_path)
    except Exception as e:
        return f"❌ File parsing failed: {e}"

    suspicious_cells = 0
    total_cells = df.shape[0] * df.shape[1]

    for row in df.itertuples(index=False):
        for cell in row:
            if is_potentially_malicious(str(cell)):
                suspicious_cells += 1

    ratio = suspicious_cells / total_cells if total_cells else 0

    if ratio > SUSPICIOUS_RATIO_THRESHOLD:
        return "🚨 Malicious"
    elif suspicious_cells > 0:
        return "⚠️ Suspicious"
    else:
        return "✅ Benign"

# === XLSX Classifier ===
def classify_xlsx(file_path):
    # File size check
    if os.path.getsize(file_path) > MAX_FILE_SIZE_MB * 1024 * 1024:
        return "❌ File too large"

    try:
        df = pd.read_excel(file_path, engine='openpyxl')
    except (OSError, zipfile.BadZipFile, ValueError):
        return "⚠️ Detected broken or malformed Excel file. Likely malicious."
    except Exception as e:
        return f"❌ File parsing failed: {e}"

    suspicious_cells = 0
    total_cells = df.shape[0] * df.shape[1]

    for row in df.itertuples(index=False):
        for cell in row:
            if is_potentially_malicious(str(cell)):
                suspicious_cells += 1

    ratio = suspicious_cells / total_cells if total_cells else 0

    if ratio > SUSPICIOUS_RATIO_THRESHOLD:
        return "🚨 Malicious"
    elif suspicious_cells > 0:
        return "⚠️ Suspicious"
    else:
        return "✅ Benign"

# === Streamlit App ===
st.title("Malware Detection for CSV and XLSX Files")

st.markdown("""
This app detects potentially malicious CSV and XLSX files based on certain heuristics such as:
- Suspicious formula patterns (e.g., `=`, `+`, `-`, `@`)
- Base64 encoded payloads
- Malicious script/payload keywords like `powershell`, `wget`, etc.
""")

# Select file type (CSV or XLSX)
file_type = st.selectbox("Select file type", ["CSV", "XLSX"])

# Upload file
uploaded_file = st.file_uploader(f"Choose a {file_type} file", type=[file_type.lower()])

if uploaded_file:
    file_path = os.path.join("temp_file." + file_type.lower())
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    st.success(f"{file_type} file uploaded successfully!")

    # Classify the uploaded file based on its type
    if file_type == "CSV":
        result = classify_csv(file_path)
    elif file_type == "XLSX":
        result = classify_xlsx(file_path)

    st.write(f"### File Classification: {result}")

    if result == "🚨 Malicious":
        st.markdown("**Warning**: This file is likely malicious! Handle with caution.")
    elif result == "⚠️ Suspicious":
        st.markdown("**Caution**: This file is suspicious, further analysis is recommended.")
    else:
        st.markdown("**Safe**: No issues detected, but always be cautious with unknown files.")
