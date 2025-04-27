import hashlib
import os
import math
import platform
import mimetypes

# Try to import magic, but provide fallback if not available
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    print("Warning: python-magic not available. Using fallback mime type detection.")
    MAGIC_AVAILABLE = False

def calculate_entropy(data):
    """
    Calculate Shannon entropy for a given byte sequence.

    Parameters:
        data (bytes): The byte sequence to analyze.

    Returns:
        float: The entropy value.
    """
    if not data:
        return 0

    # Count occurrences of each byte (0–255)
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1

    # Calculate probabilities from non-zero counts
    total_bytes = len(data)
    probabilities = [count / total_bytes for count in byte_counts if count > 0]

    # Compute Shannon entropy
    entropy = -sum(p * math.log2(p) for p in probabilities)
    return entropy

def extract_headers(file_path):
    """
    Process a file to extract metadata and calculate entropy.

    Parameters:
        file_path (str): Path to the file to process.

    Returns:
        dict: Processed file information including cryptographic hashes, file size,
              file type, MIME type, and entropy.
    """
    if not os.path.exists(file_path):
        return {"error": "File not found"}
        
    headers = {}
    
    # Get file size
    try:
        file_size = os.path.getsize(file_path)
        headers["File Size"] = f"{file_size} bytes"
    except OSError:
        headers["File Size"] = "Unknown"
    
    # Get file extension
    _, file_extension = os.path.splitext(file_path)
    headers["File Extension"] = file_extension.lower() if file_extension else "None"
    
    # Initialize mimetypes
    if not mimetypes.inited:
        mimetypes.init()
    
    # MIME Type detection - try magic first if available
    if MAGIC_AVAILABLE:
        try:
            mime = magic.Magic(mime=True)
            mime_type = mime.from_file(file_path)
            headers["MIME Type"] = mime_type
            
            # Get more detailed file info
            detailed_magic = magic.Magic()
            headers["File Info"] = detailed_magic.from_file(file_path)
        except Exception as e:
            print(f"Magic library error: {str(e)}")
            mime_type, _ = mimetypes.guess_type(file_path)
            headers["MIME Type"] = mime_type or "application/octet-stream"
            headers["File Info"] = "Could not determine (magic library error)"
    else:
        # Fallback to mimetypes
        mime_type, _ = mimetypes.guess_type(file_path)
        headers["MIME Type"] = mime_type or "application/octet-stream"
        
        # Basic file type detection based on extension
        if file_extension in ['.exe', '.dll', '.sys']:
            headers["File Info"] = f"Windows {file_extension[1:].upper()} file"
        elif file_extension in ['.pdf']:
            headers["File Info"] = "PDF document"
        elif file_extension in ['.doc', '.docx']:
            headers["File Info"] = "Microsoft Word document"
        elif file_extension in ['.txt']:
            headers["File Info"] = "Plain text file"
        elif file_extension in ['.html', '.htm']:
            headers["File Info"] = "HTML document"
        else:
            headers["File Info"] = "Binary or data file"
    
    # Read first few bytes for a simple hex dump
    try:
        with open(file_path, "rb") as f:
            header_bytes = f.read(16)  # Read first 16 bytes
            hex_header = ' '.join(f'{b:02x}' for b in header_bytes)
            headers["Hex Header"] = hex_header
    except IOError:
        headers["Hex Header"] = "Could not read file"
    
    return headers
