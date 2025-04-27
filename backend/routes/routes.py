import os
import hashlib
import time
import requests
from flask import Blueprint, request, jsonify, current_app
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import traceback # Keep for general error logging
from config import Config
from services import pe_analyzer
from concurrent.futures import ThreadPoolExecutor, as_completed
from ratelimit import limits, sleep_and_retry

# Import added analyzers from the second file
from utils.extract_headers import extract_headers
from services.pdf_classifier import predict_pdf_malware
from services.docx_analyze import analyze_docx_for_macros
from services.xlsx_analyze import classify_xlsx, classify_csv
from services.bat_analyzer import analyze_bat_file  # Import the new BAT analyzer

upload_routes = Blueprint('upload_routes', __name__)

# --- VirusTotal API configuration ---
VT_API_KEY = "ed85f6612c26d917c173df1a8547df9df0d9f114eaf1b73d15cd4e59558bf4da" # Consider env var
VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_RATE_LIMIT = 4  # 4 requests per minute
VT_REPORT_RATE = 60 / VT_RATE_LIMIT 

# --- MongoDB connection ---
def get_db():
    client = MongoClient('mongodb+srv://aadityamalani15:yHFOhT72LbpT052L@cluster0.cu7v1af.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
    return client['file_scanner']

# --- Helper Functions (VT, Hash - unchanged from previous version) ---
def calculate_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except IOError as e:
        print(f"Error reading file for hashing: {file_path} - {e}")
        return None

def scan_file_with_virustotal(file_path):
    """Upload a file to VirusTotal for scanning"""
    headers = {"x-apikey": VT_API_KEY}
    try:
        with open(file_path, "rb") as file:
            files = {"file": (os.path.basename(file_path), file)}
            response = requests.post(f"{VT_API_BASE}/files", files=files, headers=headers, timeout=60)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"VT API Error (Upload): {e}")
        # Attempt to get more details from response if available
        error_details = str(e)
        if hasattr(e, 'response') and e.response is not None:
             try:
                 error_details = f"{error_details} - Body: {e.response.text}"
             except Exception: pass # Ignore if response body can't be read
        return {"error": f"Error uploading file to VT", "details": error_details}
    except IOError as e:
        print(f"File Error (Upload): {e}")
        return {"error": f"Error reading file for VT upload", "details": str(e)}


def get_file_report(file_hash):
    """Get a file analysis report using its hash"""
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(f"{VT_API_BASE}/files/{file_hash}", headers=headers, timeout=30)
        if response.status_code == 404:
            return {"error": "Report not found", "status_code": 404}
        response.raise_for_status()
        report = response.json()
        # Basic validation
        if isinstance(report, dict) and "data" in report and isinstance(report["data"], dict) and "attributes" in report["data"]:
            return report
        else:
             print(f"VT Warning: Incomplete report data structure for hash {file_hash}")
             return {"error": "Incomplete report data", "details": "Unexpected structure from VT API"}
    except requests.exceptions.RequestException as e:
        print(f"VT API Error (Report): {e}")
        error_details = str(e)
        if hasattr(e, 'response') and e.response is not None:
             try:
                 error_details = f"{error_details} - Body: {e.response.text}"
             except Exception: pass
        status_code = e.response.status_code if hasattr(e, 'response') and e.response is not None else None
        return {"error": f"Error fetching VT report", "details": error_details, "status_code": status_code}


def get_analysis_status(analysis_id):
    """Check the status of an analysis"""
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(f"{VT_API_BASE}/analyses/{analysis_id}", headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"VT API Error (Analysis Status): {e}")
        error_details = str(e)
        if hasattr(e, 'response') and e.response is not None:
             try:
                 error_details = f"{error_details} - Body: {e.response.text}"
             except Exception: pass
        return {"error": f"Error checking VT analysis status", "details": error_details}

# --- Routes ---

@upload_routes.route('/upload', methods=['POST'])
def upload_file():
    """Handle single file upload with basic scanning, ML prediction, and VirusTotal scanning."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Save the uploaded file
    upload_folder = os.path.join(current_app.root_path, 'uploads')
    os.makedirs(upload_folder, exist_ok=True)
    file_path = os.path.join(upload_folder, file.filename)
    file.save(file_path)
    
    try:
        db = get_db()
        file_collection = db.file_scans
        
        # Calculate SHA-256 hash of the file
        file_hash = calculate_hash(file_path)
        
        # Detect MIME type
        from services.file_utils import get_file_mime_type
        mime_info = get_file_mime_type(file_path)
        
        # Check if file has been already scanned
        existing_scan = file_collection.find_one({"file_hash": file_hash})
        if existing_scan:
            # Update with MIME type if not present
            if "mime_type" not in existing_scan:
                file_collection.update_one(
                    {"_id": existing_scan["_id"]},
                    {"$set": {"mime_type": mime_info}}
                )
                existing_scan["mime_type"] = mime_info
                
            return jsonify({
                'message': 'File already scanned',
                'file_hash': file_hash,
                'report': existing_scan.get('report'),
                'status': existing_scan.get('status'),
                'scan_id': str(existing_scan.get('_id')),
                'ml_prediction': existing_scan.get('ml_prediction'),
                'ml_prediction_time': existing_scan.get('ml_prediction_time', 0),
                'feature_importances': existing_scan.get('feature_importances'),
                'mime_type': existing_scan.get('mime_type'),
                'bat_analysis': existing_scan.get('bat_analysis')  # Add BAT analysis to response
            }), 200

        # Extract basic headers to determine MIME type
        base_headers = extract_headers(file_path)
        mime_type = base_headers.get('MIME Type', '').lower() if base_headers else ""
        
        # Set defaults
        ml_prediction = "Not Applicable"
        ml_prediction_time = 0
        feature_importances = None
        analysis_time = None
        bat_analysis = None
        
        # Basic ML prediction based on file type
        # Here we use if-elif structure for simplicity
        if "vnd.microsoft.portable-executable" in mime_type or (mime_info and mime_info.get("mime_type") == "application/x-msdownload"):
            # For PE files, use SHAP explainability
            ml_start_time = time.time()
            ml_result = pe_analyzer.analyze_pe_file(file_path)
            ml_prediction_time = time.time() - ml_start_time
            
            # Extract prediction and feature importances from result
            if isinstance(ml_result, dict):
                ml_prediction = ml_result.get("prediction", "Unknown")
                feature_importances = ml_result.get("feature_importances")
                analysis_time = ml_result.get("analysis_time")
            else:
                ml_prediction = ml_result
        elif "pdf" in mime_type:
            ml_start_time = time.time()
            ml_prediction = predict_pdf_malware(file_path)
            ml_prediction_time = time.time() - ml_start_time
        elif "text/csv" in mime_type:
            ml_start_time = time.time()
            ml_prediction = classify_csv(file_path)
            ml_prediction_time = time.time() - ml_start_time
        elif "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" in mime_type:
            ml_start_time = time.time()
            ml_prediction = classify_xlsx(file_path)
            ml_prediction_time = time.time() - ml_start_time
        elif "application/msword" in mime_type:
            ml_start_time = time.time()
            ml_prediction = analyze_docx_for_macros(file_path)
            ml_prediction_time = time.time() - ml_start_time
        elif file.filename.lower().endswith('.bat') or mime_type == "text/x-msdos-batch":
            # For batch files, use our custom analyzer
            bat_analysis = analyze_bat_file(file_path)
            ml_prediction = bat_analysis.get("prediction", "Unknown")
            ml_prediction_time = bat_analysis.get("analysis_time", 0)
        else:
           ml_start_time = time.time()
           ml_prediction = "other"
           ml_prediction_time = time.time() - ml_start_time

        # Run VirusTotal scan for all file types
        scan_result = scan_file_with_virustotal(file_path)
        if "error" in scan_result:
            return jsonify(scan_result), 500
        
        analysis_id = scan_result.get("data", {}).get("id")
        
        # Prepare cumulative scan data to be stored
        scan_data = {
            'filename': file.filename,
            'file_hash': file_hash,
            'analysis_id': analysis_id,
            'status': 'pending',
            'report': scan_result,
            'scan_date': datetime.now(),
            'last_updated': datetime.now(),
            'ml_prediction': ml_prediction,
            'ml_prediction_time': ml_prediction_time if analysis_time is None else analysis_time,
            'feature_importances': feature_importances,
            'mime_type': mime_info,
            'headers': base_headers,
            'bat_analysis': bat_analysis  # Store BAT analysis if available
        }
        scan_id = file_collection.insert_one(scan_data).inserted_id
        
        # Build and return the cumulative report
        return jsonify({
            'message': 'File uploaded for scanning',
            'file_hash': file_hash,
            'analysis_id': analysis_id,
            'status': 'pending',
            'mime': mime_type,
            'report': scan_result,
            'scan_id': str(scan_id),
            'ml_prediction': ml_prediction,
            'ml_prediction_time': ml_prediction_time if analysis_time is None else analysis_time,
            'feature_importances': feature_importances,
            'mime_type': mime_info,
            'headers': base_headers,
            'bat_analysis': bat_analysis  # Include BAT analysis in response
        }), 200
    
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        # Clean up temporary file
        if os.path.exists(file_path):
            os.remove(file_path)


@upload_routes.route('/upload-batch', methods=['POST'])
def upload_batch():
    """Handle batch file uploads with parallel processing"""
    if 'files' not in request.files:
        return jsonify({'error': 'No files part'}), 400

    files = request.files.getlist('files')
    if not files:
        return jsonify({'error': 'No files selected for batch upload'}), 400

    upload_folder = os.path.join(current_app.root_path, 'uploads')
    os.makedirs(upload_folder, exist_ok=True)
    
    db = get_db()
    file_collection = db.file_scans
    results = []

    def process_file(file):
        original_filename = file.filename
        if not original_filename:
            return {'filename': 'N/A', 'error': 'Empty filename', 'status': 'error'}

        safe_filename = os.path.basename(original_filename)
        file_path = os.path.join(upload_folder, safe_filename)
        current_result = {'filename': original_filename}

        try:
            # Save file and perform ML analysis
            file.save(file_path)
            
            # Detect file type and apply appropriate classifier
            from services.file_utils import get_file_mime_type
            mime_info = get_file_mime_type(file_path)
            mime_type = mime_info.get("mime_type", "").lower() if mime_info else ""
            
            # Initialize bat_analysis to None
            bat_analysis = None
            
            # Select appropriate ML classifier based on file type
            if "application/x-msdownload" in mime_type or "executable" in mime_type:
                ml_result = pe_analyzer.analyze_pe_file(file_path)
            elif "pdf" in mime_type:
                ml_result = predict_pdf_malware(file_path)
            elif "csv" in mime_type:
                ml_result = classify_csv(file_path)
            elif "spreadsheet" in mime_type or "xlsx" in mime_type:
                ml_result = classify_xlsx(file_path)
            elif "msword" in mime_type or "docx" in mime_type:
                ml_result = analyze_docx_for_macros(file_path)
            elif original_filename.lower().endswith('.bat') or mime_type == "text/x-msdos-batch":
                # For batch files, use our custom analyzer
                bat_analysis = analyze_bat_file(file_path)
                ml_result = bat_analysis.get("prediction", "Unknown")
                current_result['bat_analysis'] = bat_analysis
            else:
                ml_result = "other"
                
            # Handle different return types (dict vs string)
            if isinstance(ml_result, dict):
                current_result['ml_prediction'] = ml_result.get("prediction", "Unknown")
                current_result['feature_importances'] = ml_result.get("feature_importances")
            else:
                current_result['ml_prediction'] = ml_result
                
            current_result['mime_type'] = mime_info
            
            # Calculate file hash
            file_hash = calculate_hash(file_path)
            if not file_hash:
                raise ValueError('Failed to calculate hash')
            current_result['file_hash'] = file_hash

            # Check database cache
            existing_scan = file_collection.find_one({"file_hash": file_hash})
            if existing_scan:
                if existing_scan.get('ml_prediction') != current_result.get('ml_prediction'):
                    update_data = {"ml_prediction": current_result.get('ml_prediction')}
                    # Update bat_analysis if available
                    if bat_analysis:
                        update_data["bat_analysis"] = bat_analysis
                    
                    file_collection.update_one(
                        {"_id": existing_scan["_id"]},
                        {"$set": update_data}
                    )
                return {
                    **current_result,
                    'status': existing_scan.get('status', 'unknown'),
                    'report': existing_scan.get('report'),
                    'scan_id': str(existing_scan.get('_id'))
                }

            # Check VT cache with rate limiting
            existing_report = vt_get_file_report(file_hash)
            if existing_report and "error" not in existing_report:
                scan_data = create_scan_data(original_filename, file_hash, existing_report, current_result.get('ml_prediction'), 
                                            current_result.get('feature_importances'), mime_info, bat_analysis)
                scan_id = file_collection.insert_one(scan_data).inserted_id
                return {
                    **current_result,
                    'status': 'complete',
                    'report': existing_report,
                    'scan_id': str(scan_id)
                }

            # Upload to VirusTotal with rate limiting
            scan_result = vt_scan_file(file_path)
            if "error" in scan_result:
                raise Exception(f"VT error: {scan_result['error']}")

            analysis_id = scan_result.get("data", {}).get("id")
            if not analysis_id:
                raise Exception("No analysis ID received from VT")

            scan_data = create_pending_scan_data(original_filename, file_hash, analysis_id, current_result.get('ml_prediction'), 
                                                current_result.get('feature_importances'), mime_info, bat_analysis)
            scan_id = file_collection.insert_one(scan_data).inserted_id
            return {
                **current_result,
                'analysis_id': analysis_id,
                'status': 'pending',
                'scan_id': str(scan_id)
            }

        except Exception as e:
            current_result.update({
                'error': str(e),
                'status': 'error',
                'details': traceback.format_exc()
            })
            return current_result
        finally:
            if os.path.exists(file_path):
                try: os.remove(file_path)
                except: pass

    # Process files in parallel with thread pool
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(process_file, file) for file in files]
        results = [future.result() for future in as_completed(futures)]

    return jsonify({
        'message': f'Processed {len(files)} files',
        'results': results
    }), 200

# Rate-limited VT API functions
@sleep_and_retry
@limits(calls=VT_RATE_LIMIT, period=60)
def vt_get_file_report(file_hash):
    """Rate-limited VT report check"""
    time.sleep(VT_REPORT_RATE)  # Add minimum delay between calls
    return get_file_report(file_hash)

@sleep_and_retry
@limits(calls=VT_RATE_LIMIT, period=60)
def vt_scan_file(file_path):
    """Rate-limited VT file upload"""
    time.sleep(VT_REPORT_RATE)  # Add minimum delay between calls
    return scan_file_with_virustotal(file_path)

def create_scan_data(filename, file_hash, report, ml_prediction, feature_importances=None, mime_info=None, bat_analysis=None):
    return {
        'filename': filename,
        'file_hash': file_hash,
        'report': report,
        'status': 'complete',
        'ml_prediction': ml_prediction,
        'feature_importances': feature_importances,
        'mime_type': mime_info,
        'scan_date': datetime.now(),
        'last_updated': datetime.now(),
        'bat_analysis': bat_analysis
    }

def create_pending_scan_data(filename, file_hash, analysis_id, ml_prediction, feature_importances=None, mime_info=None, bat_analysis=None):
    return {
        'filename': filename,
        'file_hash': file_hash,
        'analysis_id': analysis_id,
        'status': 'pending',
        'ml_prediction': ml_prediction,
        'feature_importances': feature_importances,
        'mime_type': mime_info,
        'scan_date': datetime.now(),
        'last_updated': datetime.now(),
        'bat_analysis': bat_analysis
    }

# --- Analysis Status and Report Routes (Modified to include ML Prediction) ---

@upload_routes.route('/analysis/<analysis_id>', methods=['GET'])
def check_analysis(analysis_id):
    """Check status of a VirusTotal analysis and update MongoDB"""
    try:
        db = get_db()
        file_collection = db.file_scans
        scan_record = file_collection.find_one({"analysis_id": analysis_id})

        if not scan_record:
             return jsonify({'error': 'Analysis ID not found in database'}), 404

        final_status = scan_record.get('status', 'unknown')
        ml_prediction = scan_record.get('ml_prediction') # Get ML prediction from DB

        # Only poll VT if status is still pending in DB
        if final_status == 'pending':
            print(f"Polling VT for analysis status: {analysis_id}")
            analysis_result = get_analysis_status(analysis_id) # API Call

            if "error" in analysis_result:
                print(f"Error polling VT analysis {analysis_id}: {analysis_result.get('details', analysis_result['error'])}")
                # Return error but include known details from DB
                return jsonify({
                    'error': analysis_result['error'],
                    'details': analysis_result.get('details'),
                    'analysis_id': analysis_id,
                    'ml_prediction': ml_prediction,
                    'file_hash': scan_record.get('file_hash'),
                    'filename': scan_record.get('filename')
                }), 502 # Bad Gateway

            vt_status = analysis_result.get('data', {}).get('attributes', {}).get('status', 'unknown')
            update_data = {"last_updated": datetime.now()}

            if vt_status == "completed":
                print(f"VT analysis complete for {analysis_id}. Fetching full report...")
                file_hash = scan_record.get('file_hash')
                if file_hash:
                    # time.sleep(VT_SLEEP_DURATION) # Consider rate limit if polling aggressively
                    full_report = get_file_report(file_hash)
                    if "error" not in full_report:
                        update_data.update({"status": "complete", "report": full_report})
                        final_status = "complete"
                        print(f"Successfully fetched and updated report for {file_hash}")
                    else:
                        print(f"Error fetching final report for completed analysis {analysis_id}, hash {file_hash}: {full_report.get('details', full_report['error'])}")
                        update_data.update({"status": "error_fetching_report"})
                        final_status = "error_fetching_report"
                else:
                     print(f"Error: Analysis {analysis_id} completed but no hash found in DB record.")
                     update_data.update({"status": "error_missing_hash"})
                     final_status = "error_missing_hash"
                # Update the record in DB
                file_collection.update_one({"_id": scan_record["_id"]}, {"$set": update_data})

            elif vt_status == "failed": # Or other VT terminal states
                 print(f"VT analysis failed for {analysis_id}")
                 update_data.update({"status": "failed"})
                 final_status = "failed"
                 file_collection.update_one({"_id": scan_record["_id"]}, {"$set": update_data})

        # Return the latest status including ML prediction
        return jsonify({
             'data': {
                 'id': analysis_id,
                 'type': 'analysis',
                 'attributes': { 'status': final_status } # Return our combined status
             },
             'ml_prediction': ml_prediction, # Include ML result from DB
             'file_hash': scan_record.get('file_hash'),
             'filename': scan_record.get('filename')
         }), 200

    except Exception as e:
        print(f"Unhandled Exception in /analysis/{analysis_id}: {e}")
        traceback.print_exc()
        return jsonify({'error': f'An internal server error occurred', 'details': str(e)}), 500

@upload_routes.route('/report/<file_hash>', methods=['GET'])
def get_report(file_hash):
    """Get the VirusTotal report for a file hash"""
    db = get_db()
    file_collection = db.file_scans
    
    try:
        existing_scan = file_collection.find_one({"file_hash": file_hash})
        if existing_scan:
            # If scan is complete, return the report
            if existing_scan.get('status') == 'complete' and existing_scan.get('report'):
                return jsonify({
                    'file_hash': file_hash,
                    'report': existing_scan.get('report'),
                    'status': 'complete',
                    'ml_prediction': existing_scan.get('ml_prediction'),
                    'ml_prediction_time': existing_scan.get('ml_prediction_time', 0),
                    'feature_importances': existing_scan.get('feature_importances'),
                    'mime_type': existing_scan.get('mime_type'),
                    'bat_analysis': existing_scan.get('bat_analysis'),  # Add BAT analysis data
                    'filename': existing_scan.get('filename')  # Also add filename for display
                }), 200
            
            # If scan is still pending but we have an analysis_id, check the status
            if existing_scan.get('status') == 'pending' and existing_scan.get('analysis_id'):
                analysis_id = existing_scan.get('analysis_id')
                analysis_status = get_analysis_status(analysis_id)
                
                if "data" in analysis_status and analysis_status.get('data', {}).get('attributes', {}).get('status') == 'completed':
                    # Analysis is done, get the report
                    report = get_file_report(file_hash)
                    if "error" not in report:
                        # Mark this scan as complete and save the report
                        file_collection.update_one(
                            {"_id": existing_scan.get('_id')},
                            {
                                "$set": {
                                    "status": "complete", 
                                    "report": report,
                                    "last_updated": datetime.now()
                                }
                            }
                        )
                        return jsonify({
                            'file_hash': file_hash,
                            'report': report,
                            'status': 'complete',
                            'ml_prediction': existing_scan.get('ml_prediction'),
                            'ml_prediction_time': existing_scan.get('ml_prediction_time', 0),
                            'feature_importances': existing_scan.get('feature_importances'),
                            'mime_type': existing_scan.get('mime_type'),
                            'bat_analysis': existing_scan.get('bat_analysis'),  # Add BAT analysis data
                            'filename': existing_scan.get('filename')  # Add filename
                        }), 200
                    else:
                        # Error getting report
                        return jsonify({
                            'file_hash': file_hash,
                            'error': report.get('error'),
                            'status': 'error',
                            'ml_prediction': existing_scan.get('ml_prediction'),
                            'ml_prediction_time': existing_scan.get('ml_prediction_time', 0),
                            'feature_importances': existing_scan.get('feature_importances'),
                            'mime_type': existing_scan.get('mime_type'),
                            'bat_analysis': existing_scan.get('bat_analysis'),  # Add BAT analysis data
                            'filename': existing_scan.get('filename')  # Add filename
                        }), 500
                
                # If still pending, return the pending status
                return jsonify({
                    'file_hash': file_hash,
                    'status': 'pending',
                    'analysis_id': analysis_id,
                    'ml_prediction': existing_scan.get('ml_prediction'),
                    'ml_prediction_time': existing_scan.get('ml_prediction_time', 0),
                    'feature_importances': existing_scan.get('feature_importances'),
                    'mime_type': existing_scan.get('mime_type'),
                    'bat_analysis': existing_scan.get('bat_analysis'),  # Add BAT analysis data
                    'filename': existing_scan.get('filename')  # Add filename
                }), 202
            
            # Something went wrong with the scan
            return jsonify({
                'file_hash': file_hash,
                'error': 'Scan status unclear or missing required data',
                'status': existing_scan.get('status', 'error'),
                'ml_prediction': existing_scan.get('ml_prediction'),
                'ml_prediction_time': existing_scan.get('ml_prediction_time', 0),
                'feature_importances': existing_scan.get('feature_importances'),
                'mime_type': existing_scan.get('mime_type'),
                'bat_analysis': existing_scan.get('bat_analysis'),  # Add BAT analysis data
                'filename': existing_scan.get('filename')  # Add filename
            }), 500
        
        # No scan found, check if file exists in VirusTotal
        report = get_file_report(file_hash)
        if "error" not in report:
            # Store in MongoDB for future reference
            scan_data = {
                'filename': report.get('data', {}).get('attributes', {}).get('meaningful_name', 'Unknown File'),
                'file_hash': file_hash,
                'report': report,
                'status': 'complete',
                'scan_date': datetime.now(),
                'last_updated': datetime.now(),
                'ml_prediction': 'Unknown (External File)',
                'feature_importances': None,
                'mime_type': {'mime_type': report.get('data', {}).get('attributes', {}).get('type_tag', 'unknown'), 'mime_category': 'unknown', 'mime_description': 'External file'},
                'bat_analysis': None  # External file, no BAT analysis
            }
            file_collection.insert_one(scan_data)
            
            return jsonify({
                'file_hash': file_hash,
                'report': report,
                'status': 'complete', 
                'ml_prediction': 'Unknown (External File)',
                'mime_type': {'mime_type': report.get('data', {}).get('attributes', {}).get('type_tag', 'unknown'), 'mime_category': 'unknown', 'mime_description': 'External file'},
                'bat_analysis': None,  # External file, no BAT analysis
                'filename': report.get('data', {}).get('attributes', {}).get('meaningful_name', 'Unknown File')
            }), 200
        else:
            # File not found in VirusTotal
            return jsonify({
                'file_hash': file_hash,
                'error': 'File not found in database or VirusTotal',
                'status': 'not_found'
            }), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- Other Routes (GET /scans, GET/DELETE /scan/<id> - ensure ML result is included) ---

@upload_routes.route('/scans', methods=['GET'])
def get_all_scans():
    """Get all file scans from MongoDB with pagination"""
    try:
        db = get_db()
        file_collection = db.file_scans
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        skip = (page - 1) * per_page
        total = file_collection.count_documents({})
        # Exclude large report field, ensure ml_prediction is included
        scans = list(file_collection.find({}, {'report': 0, 'scan_result_vt': 0}).sort('scan_date', -1).skip(skip).limit(per_page))

        for scan in scans:
            scan['_id'] = str(scan['_id'])
            scan.setdefault('ml_prediction', None) # Ensure field exists

        return jsonify({
            'scans': scans, 'page': page, 'per_page': per_page, 'total': total,
            'pages': (total + per_page - 1) // per_page
        }), 200
    except Exception as e:
        print(f"Error in /scans: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500
    
@upload_routes.route('/scan/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a scan from MongoDB"""
    try:
        db = get_db()
        file_collection = db.file_scans
        result = file_collection.delete_one({"_id": ObjectId(scan_id)})
        if result.deleted_count == 0:
            return jsonify({'error': 'Scan not found'}), 404
        return jsonify({'message': 'Scan deleted successfully'}), 200
    except Exception as e:
        print(f"Error deleting scan {scan_id}: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

@upload_routes.route('/dashboard', methods=['GET'])
def get_dashboard_stats():
    """Get aggregated statistics for the dashboard"""
    try:
        # Get static analysis data from file_scanner database
        file_scanner_db = get_db()  # This gets file_scanner database
        file_collection = file_scanner_db.file_scans

        # Get dynamic analysis data from dynamic_sandboxing database
        dynamic_client = MongoClient('mongodb+srv://aadityamalani15:yHFOhT72LbpT052L@cluster0.cu7v1af.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
        dynamic_db = dynamic_client['dynamic_sandboxing']
        dynamic_collection = dynamic_db.dynamic

        # Get basic statistics from static analysis
        total_scans = file_collection.count_documents({})
        total_malware = file_collection.count_documents({"ml_prediction": "Malware"})
        total_clean = file_collection.count_documents({"ml_prediction": "Clean"})
        
        # Get file type distribution
        mime_types = list(file_collection.aggregate([
            {"$group": {
                "_id": "$mime_type.mime_type",
                "count": {"$sum": 1},
                "malicious_count": {
                    "$sum": {"$cond": [{"$eq": ["$ml_prediction", "Malware"]}, 1, 0]}
                }
            }},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]))

        # Get recent scans
        recent_scans = list(file_collection.find(
            {},
            {
                'filename': 1,
                'file_hash': 1,
                'status': 1,
                'ml_prediction': 1,
                'scan_date': 1,
                'mime_type': 1,
                'feature_importances': 1
            }
        ).sort('scan_date', -1).limit(5))

        # Convert ObjectId to string for JSON serialization
        for scan in recent_scans:
            scan['_id'] = str(scan['_id'])

        # Get top malware features
        feature_importance_agg = []
        scans_with_features = file_collection.find(
            {"feature_importances": {"$ne": None}},
            {"feature_importances": 1}
        )
        
        feature_counts = {}
        for scan in scans_with_features:
            if scan.get('feature_importances'):
                for feature in scan['feature_importances']:
                    name = feature.get('feature')
                    importance = feature.get('importance', 0)
                    if name not in feature_counts:
                        feature_counts[name] = {
                            'total_importance': 0,
                            'count': 0,
                            'description': feature.get('description', '')
                        }
                    feature_counts[name]['total_importance'] += importance
                    feature_counts[name]['count'] += 1

        for feature, data in feature_counts.items():
            avg_importance = data['total_importance'] / data['count']
            feature_importance_agg.append({
                'feature': feature,
                'average_importance': avg_importance,
                'description': data['description'],
                'occurrence_count': data['count']
            })

        feature_importance_agg.sort(key=lambda x: x['average_importance'], reverse=True)
        top_features = feature_importance_agg[:10]

        # Get scan trends (last 7 days)
        from datetime import datetime, timedelta
        seven_days_ago = datetime.now() - timedelta(days=7)
        
        daily_scans = list(file_collection.aggregate([
            {
                "$match": {
                    "scan_date": {"$gte": seven_days_ago}
                }
            },
            {
                "$group": {
                    "_id": {
                        "$dateToString": {
                            "format": "%Y-%m-%d",
                            "date": "$scan_date"
                        }
                    },
                    "total": {"$sum": 1},
                    "malware": {
                        "$sum": {
                            "$cond": [{"$eq": ["$ml_prediction", "Malware"]}, 1, 0]
                        }
                    },
                    "clean": {
                        "$sum": {
                            "$cond": [{"$eq": ["$ml_prediction", "Clean"]}, 1, 0]
                        }
                    }
                }
            },
            {"$sort": {"_id": 1}}
        ]))

        # Get dynamic analysis stats
        total_dynamic = dynamic_collection.count_documents({})
        dynamic_malware = dynamic_collection.count_documents({"verdict": "malicious"})
        
        # Get behavior categories distribution from dynamic analysis
        dynamic_stats = list(dynamic_collection.aggregate([
            {"$unwind": "$signatures"},
            {"$group": {
                "_id": "$signatures.category",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}},
            {"$limit": 5}
        ]))

        # Get top dynamic behaviors
        dynamic_behaviors = list(dynamic_collection.aggregate([
            {"$unwind": "$signatures"},
            {"$group": {
                "_id": "$signatures.name",
                "count": {"$sum": 1},
                "category": {"$first": "$signatures.category"}
            }},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]))

        return jsonify({
            'summary': {
                'total_scans': total_scans,
                'total_malware': total_malware,
                'total_clean': total_clean,
                'detection_rate': (total_malware / total_scans * 100) if total_scans > 0 else 0,
                'total_dynamic_scans': total_dynamic,
                'dynamic_malware': dynamic_malware
            },
            'mime_distribution': mime_types,
            'recent_scans': recent_scans,
            'top_features': top_features,
            'daily_trends': daily_scans,
            'dynamic_stats': dynamic_stats,
            'dynamic_behaviors': dynamic_behaviors
        }), 200

    except Exception as e:
        print(f"Error generating dashboard stats: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500
    finally:
        if 'dynamic_client' in locals():
            dynamic_client.close()