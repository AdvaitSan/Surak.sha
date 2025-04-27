import pefile
import os
import datetime
import hashlib
import math
import array
import json
from collections import Counter

def extract_pe_features(file_path):
    """
    Extract features from a PE file for malware analysis.
    
    Parameters:
        file_path (str): Path to the PE file
        
    Returns:
        dict: Dictionary containing PE file features
    """
    try:
        # Check if file exists
        if not os.path.isfile(file_path):
            return {"error": "File does not exist"}
            
        # Check if file is a PE file
        try:
            pe = pefile.PE(file_path)
        except pefile.PEFormatError:
            return {"error": "Not a valid PE file"}
            
        # Extract basic PE information
        features = {}
        
        # File metadata
        features["filename"] = os.path.basename(file_path)
        features["file_size"] = os.path.getsize(file_path)
        
        # Calculate file hashes
        with open(file_path, 'rb') as f:
            data = f.read()
            features["md5"] = hashlib.md5(data).hexdigest()
            features["sha1"] = hashlib.sha1(data).hexdigest()
            features["sha256"] = hashlib.sha256(data).hexdigest()
        
        # PE Header information
        features["machine_type"] = hex(pe.FILE_HEADER.Machine)
        features["timestamp"] = datetime.datetime.fromtimestamp(
            pe.FILE_HEADER.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S')
        features["number_of_sections"] = pe.FILE_HEADER.NumberOfSections
        features["pointer_to_symbol_table"] = pe.FILE_HEADER.PointerToSymbolTable
        features["number_of_symbols"] = pe.FILE_HEADER.NumberOfSymbols
        features["size_of_optional_header"] = pe.FILE_HEADER.SizeOfOptionalHeader
        features["characteristics"] = hex(pe.FILE_HEADER.Characteristics)
        
        # Optional Header
        if hasattr(pe, 'OPTIONAL_HEADER'):
            features["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)
            features["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            features["subsystem"] = pe.OPTIONAL_HEADER.Subsystem
            features["dll_characteristics"] = hex(pe.OPTIONAL_HEADER.DllCharacteristics)
        
        # Section information
        features["sections"] = []
        for section in pe.sections:
            section_info = {
                "name": section.Name.decode('utf-8', 'ignore').strip('\x00'),
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": section.get_entropy()
            }
            features["sections"].append(section_info)
        
        # Import information
        features["imports"] = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', 'ignore')
                features["imports"][dll_name] = []
                for imp in entry.imports:
                    if imp.name:
                        features["imports"][dll_name].append(imp.name.decode('utf-8', 'ignore'))
                    else:
                        features["imports"][dll_name].append(f"ordinal_{imp.ordinal}")
        
        # Export information
        features["exports"] = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    features["exports"].append(exp.name.decode('utf-8', 'ignore'))
                else:
                    features["exports"].append(f"ordinal_{exp.ordinal}")
        
        # Resources
        features["resources"] = []
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data_rva = resource_lang.data.struct.OffsetToData
                                size = resource_lang.data.struct.Size
                                features["resources"].append({
                                    "type": resource_type.id,
                                    "id": resource_id.id,
                                    "language": resource_lang.id,
                                    "size": size,
                                    "rva": data_rva
                                })
        
        # Calculate overall file entropy
        features["file_entropy"] = calculate_entropy(data)
        
        # Extract strings
        features["strings"] = extract_strings(data)
        
        # Check for packing
        features["packing_likelihood"] = check_packing_likelihood(pe, features["file_entropy"])
        
        # TLS callbacks
        features["has_tls_callbacks"] = has_tls_callbacks(pe)
        
        # Digital signature
        features["is_signed"] = is_signed(pe)
        
        return features
        
    except Exception as e:
        return {"error": f"Error analyzing PE file: {str(e)}"}

def calculate_entropy(data):
    """Calculate Shannon entropy of data"""
    if not data:
        return 0
    
    byte_counts = Counter(bytearray(data))
    file_size = len(data)
    entropy = 0
    
    for count in byte_counts.values():
        probability = count / file_size
        entropy -= probability * math.log2(probability)
        
    return entropy

def extract_strings(data, min_length=4):
    """Extract ASCII and Unicode strings from binary data"""
    strings = []
    current_string = ""
    
    # ASCII strings
    for byte in data:
        if 32 <= byte <= 126:  # Printable ASCII
            current_string += chr(byte)
        else:
            if len(current_string) >= min_length:
                strings.append(current_string)
            current_string = ""
    
    if len(current_string) >= min_length:
        strings.append(current_string)
    
    # Return top 100 strings to avoid overwhelming the results
    return strings[:100]

def check_packing_likelihood(pe, entropy):
    """Estimate likelihood of file being packed"""
    # High entropy is often indicative of packing
    if entropy > 7.0:
        likelihood = "High"
    elif entropy > 6.5:
        likelihood = "Medium"
    else:
        likelihood = "Low"
    
    # Check for common packer sections
    packer_sections = [".upx", "UPX", ".aspack", "ASPack", ".nsp", ".enigma"]
    for section in pe.sections:
        name = section.Name.decode('utf-8', 'ignore').strip('\x00')
        if any(packer in name for packer in packer_sections):
            likelihood = "High"
            break
    
    # Few imports often indicates packing
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        import_count = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
        if import_count < 10:
            likelihood = "High"
    else:
        likelihood = "High"  # No imports is suspicious
    
    return likelihood

def has_tls_callbacks(pe):
    """Check if the PE file has TLS callbacks (often used for anti-debugging)"""
    return hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS is not None

def is_signed(pe):
    """Check if the PE file is digitally signed"""
    return (hasattr(pe, 'OPTIONAL_HEADER') and 
            hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY') and
            len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4 and
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress != 0)

def generate_pe_report(pe_features):
    """
    Generate a JSON report from the PE features.
    
    Parameters:
        pe_features (dict): PE file features as returned by extract_pe_features
        
    Returns:
        str: A JSON-formatted report string
    """
    if "error" in pe_features:
        return {"error": pe_features["error"]}
    
    report = {
        "basic_information": {
           
            "timestamp": pe_features.get("timestamp", "N/A"),
            "file_entropy": pe_features.get("file_entropy", "N/A"),
            "packing_likelihood": pe_features.get("packing_likelihood", "N/A"),
            "is_signed": pe_features.get("is_signed", "N/A"),
            "has_tls_callbacks": pe_features.get("has_tls_callbacks", "N/A"),
        },
        "pe_header_information": {
            "machine_type": pe_features.get("machine_type", "N/A"),
            "number_of_sections": pe_features.get("number_of_sections", "N/A"),
            "characteristics": pe_features.get("characteristics", "N/A"),
            "entry_point": pe_features.get("entry_point", "N/A"),
            "image_base": pe_features.get("image_base", "N/A"),
            "subsystem": pe_features.get("subsystem", "N/A"),
        },
        "sections": pe_features.get("sections", []),
        "imports": pe_features.get("imports", {}),
        "exports": pe_features.get("exports", []),
        "resources": pe_features.get("resources", []),
    }
    
    return (report)

if __name__ == "__main__":
    # Example usage
    file_path = "path/to/your/executable.exe"
    if os.path.exists(file_path):
        features = extract_pe_features(file_path)
        report = generate_pe_report(features)
        print(report)
        
        # Optionally save the features to a JSON file
        with open(f"{os.path.basename(file_path)}_analysis.json", 'w') as f:
            json.dump(features, f, indent=4)
    else:
        print(f"File not found: {file_path}")
