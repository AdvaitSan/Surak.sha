import os
import logging

from .extract_headers import extract_headers
from .extraction.yara_scan import scan_with_yara
from .extraction.pefile_handle import extract_pe_features,generate_pe_report
def process_file(save_path, filename):
    # Extract generic headers and metadata from the file.
    file_info = extract_headers(save_path)
    
    # Perform YARA scanning using the provided rules directory.
    try:
        yara_output = scan_with_yara(save_path)
        file_info['yara'] = yara_output
    except Exception as e:
        logging.error(f"YARA scanning failed: {e}")
        yara_output = None
    
    # Determine file information from headers and file extension.
    file_type_info = file_info.get('file_type', '').lower()
    extension = os.path.splitext(filename)[1].lower()


    
    # Process based on file type.
    if ("pe32" in file_type_info or "windows executable" in file_type_info) or extension in ['.exe', '.dll']:
        # Extract PE features and generate a report.
        try:
            pe_features = extract_pe_features(save_path)
            file_info['pe_report']=generate_pe_report(pe_features)
        except Exception as e:
            logging.error(f"PE feature extraction failed: {e}")

    elif "pdf" in file_type_info or extension == ".pdf":
        print("PDF processed")
    elif "csv" in file_type_info or extension == ".csv":
        print("CSV processed")
    elif "docx" in file_type_info or extension == ".docx" or "microsoft word" in file_type_info:
        print("DOCX processed")
    elif extension == ".bat":
        print("Batch script processed")
    elif extension == ".sh":
        print("Shell script processed")
    

    #remove file
    try:
        os.remove(save_path)
        logging.info(f"File {save_path} deleted successfully.")
    except Exception as e:
        logging.error(f"Failed to delete file {save_path}: {e}")
    # Return only the basic extracted information.
    return file_info

