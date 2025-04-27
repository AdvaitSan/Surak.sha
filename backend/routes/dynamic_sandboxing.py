import os
import json
import time
import hashlib
import requests
from flask import Blueprint, request, jsonify
from pymongo import MongoClient
from datetime import datetime

# MongoDB client setup
client = MongoClient('mongodb+srv://aadityamalani15:yHFOhT72LbpT052L@cluster0.cu7v1af.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
db = client['dynamic_sandboxing']
dynamic_collection = db.dynamic

#  API configuration
API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY", "fhu8ys2tb683c59bmoihtdhl6b87974cyw91z8l407782d23ls6gn9kr70355d5a")
HEADERS = {
    "User-Agent": "Falcon Sandbox",
    "api-key": API_KEY
}
BASE_URL = "https://www.hybrid-analysis.com/api/v2"

# Create Blueprint
dynamic_routes = Blueprint('dynamic_routes', __name__)

# Helper function to calculate SHA256
def calculate_sha256(file_data) -> str:
    sha256 = hashlib.sha256()
    sha256.update(file_data)
    return sha256.hexdigest()

# Submit a file for dynamic analysis
@dynamic_routes.route('/dynamic-submit', methods=['POST'])
def submit_file_for_analysis():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        uploaded_file = request.files['file']
        file_data = uploaded_file.read()
        file_hash = calculate_sha256(file_data)
        filename = uploaded_file.filename
        
        print(f"DEBUG: Processing file upload: {filename} (hash: {file_hash})")
        
        # Check if analysis already exists in the database
        existing_analysis = dynamic_collection.find_one({"file_hash": file_hash})
        if existing_analysis:
            print(f"DEBUG: Found existing analysis for {file_hash} with status {existing_analysis.get('status')}")
            # If analysis is complete, return it immediately
            if existing_analysis.get("status") == "completed":
                return jsonify({
                    "file_hash": file_hash,
                    "sha256": file_hash,
                    "status": "completed",
                    "message": "Analysis already exists",
                    "job_id": existing_analysis.get("job_id"),
                    "submission_id": existing_analysis.get("submission_id")
                }), 200
            
            # If analysis is pending, return the status
            elif existing_analysis.get("status") == "pending":
                return jsonify({
                    "file_hash": file_hash,
                    "sha256": file_hash,
                    "status": "pending",
                    "message": "Analysis in progress",
                    "job_id": existing_analysis.get("job_id"),
                    "submission_id": existing_analysis.get("submission_id")
                }), 200
        
        # Submit the file to 
        url = f"{BASE_URL}/submit/file"
        files = {"file": (filename, file_data)}
        
        # We use environment_id 160 for Windows 10 64-bit
        data = {"environment_id": 160}
        
        response = requests.post(url, headers=HEADERS, files=files, data=data)
        
        # Accept both 200 and 201 status codes as success (201 means Created)
        if response.status_code not in [200, 201]:
            error_msg = f" submission failed: {response.status_code}"
            print(f"DEBUG: {error_msg}")
            print(f"DEBUG: Response text: {response.text}")
            return jsonify({
                "error": error_msg,
                "details": response.text
            }), 500
        
        result = response.json()
        print(f"DEBUG:  response data: {result}")
        job_id = result.get("job_id")
        submission_id = result.get("submission_id")
        
        if not job_id:
            error_msg = "Submission failed: No job ID returned"
            print(f"DEBUG: {error_msg}")
            return jsonify({
                "error": error_msg,
                "details": result
            }), 500
        
        # Store the submission info in the database
        print(f"DEBUG: Storing job in MongoDB: file_hash={file_hash}, job_id={job_id}")
        db_result = dynamic_collection.insert_one({
            "file_hash": file_hash,
            "filename": filename,
            "job_id": job_id,
            "submission_id": submission_id,
            "status": "pending",
            "submission_time": datetime.now(),
            "last_checked": datetime.now()
        })
        print(f"DEBUG: MongoDB insert result: {db_result.inserted_id}")
        
        return jsonify({
            "sha256": file_hash,
            "file_hash": file_hash,
            "job_id": job_id,
            "submission_id": submission_id,
            "status": "pending",
            "message": "File submitted for dynamic analysis"
        }), 200
        
    except Exception as e:
        print(f"DEBUG: Exception in dynamic-submit: {str(e)}")
        import traceback
        print(f"DEBUG: Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

# Check the status of a dynamic analysis
@dynamic_routes.route('/dynamic-status/<job_id>', methods=['GET'])
def check_analysis_status(job_id):
    try:
        # Check if we have this job in the database
        job = dynamic_collection.find_one({"job_id": job_id})
        if not job:
            print(f"DEBUG: Job {job_id} not found in database")
            return jsonify({"error": "Job not found"}), 404
        
        print(f"DEBUG: Found job {job_id} with status {job.get('status')}")
        
        # If job is already marked as completed, return the status
        if job.get("status") == "completed":
            return jsonify({"status": "completed", "file_hash": job.get("file_hash")}), 200
        
        # If job is marked as failed, return the status
        if job.get("status") == "failed":
            return jsonify({"status": "failed", "error": job.get("error")}), 200
        
        # FIRST try direct lookup with SHA256 (this is how the Streamlit version works)
        if job.get("file_hash"):
            print(f"DEBUG: Trying direct SHA256 lookup for {job.get('file_hash')}")
            sha256_url = f"{BASE_URL}/overview/{job.get('file_hash')}"
            try:
                sha256_response = requests.get(sha256_url, headers=HEADERS)
                print(f"DEBUG: Direct lookup response status: {sha256_response.status_code}")
                
                if sha256_response.status_code == 200:
                    sha256_data = sha256_response.json()
                    verdict = sha256_data.get("verdict")
                    
                    if verdict:
                        print(f"DEBUG: Found verdict via SHA256 lookup: {verdict}")
                        # Process and store the full report data
                        threat_score = sha256_data.get("threat_score", 0)
                        
                        # Extract key behavioral indicators from the SHA256 data
                        signatures = []
                        for behavior in sha256_data.get("signatures", []):
                            signatures.append({
                                "description": behavior.get("name", "Unknown"),
                                "severity": behavior.get("severity", "low"),
                                "mitre_tactics": behavior.get("attack_ids", [])
                            })
                        
                        # Update the database as completed with the data we have
                        dynamic_collection.update_one(
                            {"job_id": job_id},
                            {
                                "$set": {
                                    "status": "completed",
                                    "completion_time": datetime.now(),
                                    "last_checked": datetime.now(),
                                    "verdict": verdict,
                                    "threat_score": threat_score,
                                    "signatures": signatures,
                                    "scan_time": sha256_data.get("analysis_time", 0),
                                    "environment": {
                                        "os": "Windows 10",
                                        "architecture": "x64" 
                                    },
                                    "classification": sha256_data.get("classification", []),
                                    "report_data": sha256_data
                                }
                            }
                        )
                        return jsonify({
                            "status": "completed",
                            "file_hash": job.get("file_hash")
                        }), 200
            except Exception as e:
                print(f"DEBUG: Exception in direct lookup: {str(e)}")
        
        # Then fallback to checking job status via API
        url = f"{BASE_URL}/report/{job_id}/summary"
        print(f"DEBUG: Checking status from API: {url}")
        try:
            response = requests.get(url, headers=HEADERS)
            print(f"DEBUG: API response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                job_status = data.get("status")
                print(f"DEBUG: Job status from API: {job_status}")
                
                # Update the database with the latest status
                if job_status == "finished":
                    # Use the direct lookup approach since we know it works better
                    return jsonify({
                        "status": "pending", 
                        "message": "Analysis is near completion, fetching results...",
                        "file_hash": job.get("file_hash")
                    }), 200
            
            # For any other job status or API error, update last checked time
            dynamic_collection.update_one(
                {"job_id": job_id},
                {"$set": {"last_checked": datetime.now()}}
            )
            
        except Exception as e:
            print(f"DEBUG: Exception checking job status: {str(e)}")
        
        # At this point, we'll just return pending and let the client keep polling
        return jsonify({
            "status": "pending",
            "message": "Analysis in progress, please wait...",
            "file_hash": job.get("file_hash")
        }), 200
            
    except Exception as e:
        print(f"DEBUG: Exception in check_analysis_status: {str(e)}")
        import traceback
        print(f"DEBUG: Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

# Get the dynamic analysis report
@dynamic_routes.route('/dynamic-report/<file_hash>', methods=['GET'])
def get_dynamic_report(file_hash):
    try:
        print(f"DEBUG: Retrieving dynamic report for hash: {file_hash}")
        
        # Find the report in the database
        report = dynamic_collection.find_one({"file_hash": file_hash})
        
        if not report:
            print(f"DEBUG: No report found for hash: {file_hash}")
            return jsonify({"error": "Report not found"}), 404
        
        print(f"DEBUG: Found report with status: {report.get('status')}")
        
        # If the report is pending, check its status
        if report.get("status") == "pending":
            # Optionally, we could trigger a status check here to see if it's actually complete
            return jsonify({
                "status": "pending",
                "message": "Analysis is still in progress",
                "job_id": report.get("job_id")
            }), 200
            
        # If the report failed, return the error
        if report.get("status") == "failed":
            return jsonify({
                "status": "failed",
                "error": report.get("error")
            }), 200
            
        # Format and return the report
        result = {
            "filename": report.get("filename"),
            "sha256": report.get("file_hash"),
            "job_id": report.get("job_id"),
            "status": report.get("status"),
            "analysis_date": report.get("completion_time"),
            "verdict": report.get("verdict"),
            "threat_score": report.get("threat_score"),
            "signatures": report.get("signatures"),
            "network": report.get("network"),
            "filesystem": report.get("filesystem"),
            "processes": report.get("processes"),
            "scan_time": report.get("scan_time"),
            "environment": report.get("environment"),
            "classification": report.get("classification")
        }
        
        print(f"DEBUG: Returning complete report for hash: {file_hash}")
        return jsonify(result), 200
        
    except Exception as e:
        print(f"DEBUG: Exception in dynamic-report: {str(e)}")
        import traceback
        print(f"DEBUG: Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

# Start a dynamic analysis for a file that's already been uploaded
@dynamic_routes.route('/run-dynamic-analysis', methods=['POST'])
def run_dynamic_analysis():
    try:
        data = request.json
        if not data or 'file_hash' not in data:
            return jsonify({"error": "File hash required"}), 400
        
        file_hash = data['file_hash']
        filename = data.get('filename', f"file_{file_hash}")
        
        # Check if analysis already exists in the database
        existing_analysis = dynamic_collection.find_one({"file_hash": file_hash})
        if existing_analysis:
            # If analysis is complete or pending, return it
            if existing_analysis.get("status") in ["completed", "pending"]:
                return jsonify({
                    "file_hash": file_hash,
                    "status": existing_analysis.get("status"),
                    "message": f"Analysis already {existing_analysis.get('status')}",
                    "job_id": existing_analysis.get("job_id")
                }), 200
        
        # Check if we have the file in VirusTotal reports
        vt_report = db.reports.find_one({"file_hash": file_hash})
        if not vt_report:
            return jsonify({"error": "File not found in reports"}), 404
        
        # For now, we'll simulate starting a dynamic analysis
        # In a real implementation, you would need to:
        # 1. Retrieve the file from storage or have the user upload it
        # 2. Submit it to 
        
        # Simulate a job ID for now
        job_id = f"job_{int(time.time())}_{file_hash[:8]}"
        submission_id = f"sub_{int(time.time())}_{file_hash[:8]}"
        
        # Store the submission info in the database
        dynamic_collection.insert_one({
            "file_hash": file_hash,
            "filename": filename,
            "job_id": job_id,
            "submission_id": submission_id,
            "status": "pending",
            "submission_time": datetime.now(),
            "last_checked": datetime.now()
        })
        
        # In a real implementation, you would start the analysis process here
        # For demonstration, we'll just return the job ID
        
        return jsonify({
            "file_hash": file_hash,
            "job_id": job_id,
            "submission_id": submission_id,
            "status": "pending",
            "message": "File queued for dynamic analysis"
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Direct lookup endpoint for synchronous polling (like in Dynamic.py)
@dynamic_routes.route('/hybrid-analysis-direct/<file_hash>', methods=['GET'])
def direct_hybrid_analysis_lookup(file_hash):
    """
    This endpoint directly queries the  API for results
    without using job_id, similar to how the Streamlit version works.
    """
    try:
        print(f"DEBUG: Direct lookup for file hash: {file_hash}")
        
        # Check if we already have results in the database
        existing_report = dynamic_collection.find_one({"file_hash": file_hash, "status": "completed"})
        if existing_report:
            print(f"DEBUG: Found existing completed report in database")
            # Return the existing report
            result = {
                "filename": existing_report.get("filename"),
                "sha256": existing_report.get("file_hash"),
                "job_id": existing_report.get("job_id"),
                "status": existing_report.get("status"),
                "analysis_date": existing_report.get("completion_time"),
                "verdict": existing_report.get("verdict"),
                "threat_score": existing_report.get("threat_score"),
                "signatures": existing_report.get("signatures"),
                "network": existing_report.get("network"),
                "filesystem": existing_report.get("filesystem"),
                "processes": existing_report.get("processes"),
                "scan_time": existing_report.get("scan_time"),
                "environment": existing_report.get("environment"),
                "classification": existing_report.get("classification")
            }
            return jsonify(result), 200
        
        # Otherwise, try direct lookup with 
        url = f"{BASE_URL}/overview/{file_hash}"
        print(f"DEBUG: Querying  API directly: {url}")
        response = requests.get(url, headers=HEADERS)
        print(f"DEBUG: Direct API response status: {response.status_code}")
        
        if response.status_code != 200:
            print(f"DEBUG: Direct lookup failed with status {response.status_code}")
            return jsonify({"error": "Direct lookup failed", "status": "pending"}), 202  # 202 = Accepted but processing
        
        data = response.json()
        print(f"DEBUG: Got direct API response with data: {data.keys() if isinstance(data, dict) else 'Not a dict'}")
        
        # Check if we have a verdict
        verdict = data.get("verdict")
        if not verdict:
            print(f"DEBUG: No verdict found in response, still processing")
            return jsonify({"message": "Analysis still in progress", "status": "pending"}), 202
        
        print(f"DEBUG: Found verdict: {verdict}")
        
        # Process the report data
        threat_score = data.get("threat_score", 0)
        
        # Extract behavioral signatures
        signatures = []
        for behavior in data.get("signatures", []):
            signatures.append({
                "description": behavior.get("name", "Unknown"),
                "severity": behavior.get("severity", "low"),
                "mitre_tactics": behavior.get("attack_ids", []),
                "detail": behavior.get("description", "")
            })
        
        # Extract network activity - simplified compared to job_id method
        network = {
            "connections": []
        }
        for connection in data.get("network_connections", []):
            network["connections"].append({
                "destination_ip": connection.get("ip"),
                "port": connection.get("port"),
                "protocol": connection.get("protocol", "TCP"),
                "malicious": connection.get("malicious", False),
                "url": connection.get("url", "")
            })
        
        # Extract file system and process data as available
        filesystem = []
        processes = []
        
        # Store the results in the database
        report_entry = {
            "file_hash": file_hash,
            "job_id": f"direct_{int(time.time())}",  # Generate a synthetic job ID for direct lookups
            "status": "completed",
            "submission_time": datetime.now(),
            "completion_time": datetime.now(),
            "last_checked": datetime.now(),
            "verdict": verdict,
            "threat_score": threat_score,
            "signatures": signatures,
            "network": network,
            "filesystem": filesystem,
            "processes": processes,
            "scan_time": data.get("analysis_time", 0),
            "environment": {
                "os": "Windows 10",
                "architecture": "x64" 
            },
            "classification": data.get("classification", []),
            "report_data": data
        }
        
        # Check if we have a pending entry to update
        existing_pending = dynamic_collection.find_one({"file_hash": file_hash, "status": "pending"})
        if existing_pending:
            print(f"DEBUG: Updating existing pending entry in database")
            dynamic_collection.update_one(
                {"_id": existing_pending["_id"]},
                {"$set": report_entry}
            )
        else:
            print(f"DEBUG: Inserting new completed entry in database")
            dynamic_collection.insert_one(report_entry)
        
        # Return the processed data
        result = {
            "sha256": file_hash,
            "file_hash": file_hash,
            "status": "completed",
            "verdict": verdict,
            "threat_score": threat_score,
            "signatures": signatures,
            "network": network,
            "filesystem": filesystem,
            "processes": processes,
            "scan_time": data.get("analysis_time", 0),
            "environment": {
                "os": "Windows 10",
                "architecture": "x64" 
            },
            "classification": data.get("classification", [])
        }
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"DEBUG: Exception in direct lookup: {str(e)}")
        import traceback
        print(f"DEBUG: Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e), "status": "error"}), 500 

# Simple direct overview endpoint (exactly like in Streamlit version)
@dynamic_routes.route('/overview/<sha256>', methods=['GET'])
def get_overview_by_sha256(sha256):
    """
    Pure passthrough to  overview endpoint, 
    exactly like get_report_by_sha256 in Dynamic.py
    """
    try:
        print(f"DEBUG: Direct passthrough to  overview for {sha256}")
        url = f"{BASE_URL}/overview/{sha256}"
        response = requests.get(url, headers=HEADERS)
        
        if response.status_code != 200:
            print(f"DEBUG: Overview lookup failed with status {response.status_code}")
            return jsonify({"error": "Overview lookup failed"}), response.status_code
        
        # Return the exact JSON response from 
        return response.json(), 200
        
    except Exception as e:
        print(f"DEBUG: Exception in overview lookup: {str(e)}")
        import traceback
        print(f"DEBUG: Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500 