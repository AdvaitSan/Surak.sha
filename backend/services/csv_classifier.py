# csv_classifier.py

import os
import re
import base64
import pandas as pd

# === Config ===
MAX_FILE_SIZE_MB = 25
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
        print("❌ File too large")
        return "Malicious"

    try:
        df = pd.read_csv(file_path)
    except Exception as e:
        print(f"❌ File parsing failed: {e}")
        return "Malicious"

    suspicious_cells = 0
    total_cells = df.shape[0] * df.shape[1]

    for row in df.itertuples(index=False):
        for cell in row:
            if is_potentially_malicious(str(cell)):
                suspicious_cells += 1

    ratio = suspicious_cells / total_cells if total_cells else 0

    if ratio > SUSPICIOUS_RATIO_THRESHOLD:
        return "Malicious"
    elif suspicious_cells > 0:
        return "Suspicious"
    else:
        return "Benign"

# === Main Execution ===
if __name__ == "__main__":
    file_path = input("Enter the CSV file path to classify: ")
    result = classify_csv(file_path)
    print(f"Classification: {result}")
