import streamlit as st
import requests
import hashlib
import time

API_KEY = ""
HEADERS = {
    "User-Agent": "Falcon Sandbox",
    "api-key": API_KEY
}
BASE_URL = "https://www.hybrid-analysis.com/api/v2"

# Function to calculate SHA256 (optional for display)
def calculate_sha256(file) -> str:
    sha256 = hashlib.sha256()
    for chunk in iter(lambda: file.read(4096), b""):
        sha256.update(chunk)
    file.seek(0)
    return sha256.hexdigest()

# Function to submit the file for analysis
def submit_file(uploaded_file, environment_id=160):
    url = f"{BASE_URL}/submit/file"
    files = {"file": (uploaded_file.name, uploaded_file.getvalue())}
    data = {"environment_id": environment_id}
    response = requests.post(url, headers=HEADERS, files=files, data=data)
    return response.json()

# Function to get report summary using SHA256
def get_report_by_sha256(sha256): 
    url = f"{BASE_URL}/overview/{sha256}"
    response = requests.get(url, headers=HEADERS)
    return response.json()

# Streamlit UI
st.set_page_config(page_title="Hybrid Analysis File Scanner", layout="centered")
st.title("🔬 Hybrid Analysis File Scanner")

uploaded_file = st.file_uploader("Upload a file for malware analysis", type=None)

if uploaded_file is not None:
    st.write("Calculating SHA256...")
    file_hash = calculate_sha256(uploaded_file)
    st.code(file_hash, language="text")

    with st.spinner("Submitting to Hybrid Analysis..."):
        submit_result = submit_file(uploaded_file, environment_id=160)
        job_id = submit_result.get("job_id")
        submission_id = submit_result.get("submission_id")
        
        if not job_id:
            st.error("Submission failed. Response:")
            st.json(submit_result)
        else:
            st.success(f"File submitted successfully! Job ID: {job_id} Submission ID: {submission_id}")

            # Polling for the report status
            st.write("Waiting for the analysis report... (this may take some time)")

            # Wait for the submission to process
            while True:
                st.write("Polling for the results...")
                time.sleep(10)  # Poll every 10 seconds

                # Fetch report based on SHA256
                report = get_report_by_sha256(file_hash)
                if report:
                    verdict = report.get("verdict")
                    if verdict:
                        st.success(f"Analysis complete! Verdict: {verdict}")
                        st.subheader("📄 Detailed Report")
                        st.json(report)
                        break
                else:
                    st.warning("Analysis is still in progress. Retrying...")
