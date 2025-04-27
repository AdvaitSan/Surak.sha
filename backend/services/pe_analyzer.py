# backend/services/pe_analyzer.py

import os
import joblib
import pefile
import pandas as pd
import math
import traceback
import numpy as np
import shap  # Add SHAP for explainable AI

# --- Constants and Model Loading ---
# Assumes 'models' directory is at the same level as 'services' inside 'backend'
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'malwareclassifier-V2.pkl')
ALLOWED_ML_EXTENSIONS = {'exe', 'dll'}
_ML_MODEL = None # Internal variable to hold the loaded model
_FEATURE_ORDER = [ # Define the exact expected feature order for the model
    'MajorLinkerVersion', 'MinorOperatingSystemVersion', 'MajorSubsystemVersion',
    'SizeOfStackReserve', 'TimeDateStamp', 'MajorOperatingSystemVersion',
    'Characteristics', 'ImageBase', 'Subsystem', 'MinorImageVersion',
    'MinorSubsystemVersion', 'SizeOfInitializedData', 'DllCharacteristics',
    'DirectoryEntryExport', 'ImageDirectoryEntryExport', 'CheckSum',
    'DirectoryEntryImportSize', 'SectionMaxChar', 'MajorImageVersion',
    'AddressOfEntryPoint', 'SectionMinEntropy', 'SizeOfHeaders',
    'SectionMinVirtualsize'
]

# Feature descriptions for explainability
_FEATURE_DESCRIPTIONS = {
    'MajorLinkerVersion': 'Major version of the linker used',
    'MinorOperatingSystemVersion': 'Minor version of the required OS',
    'MajorSubsystemVersion': 'Major version of the subsystem',
    'SizeOfStackReserve': 'Size of stack memory reserved',
    'TimeDateStamp': 'Time the executable was created',
    'MajorOperatingSystemVersion': 'Major version of the required OS',
    'Characteristics': 'Characteristics flag of the executable',
    'ImageBase': 'Preferred address when loaded in memory',
    'Subsystem': 'Subsystem required to run the executable',
    'MinorImageVersion': 'Minor version of the executable',
    'MinorSubsystemVersion': 'Minor version of the subsystem',
    'SizeOfInitializedData': 'Size of initialized data section',
    'DllCharacteristics': 'Characteristics of DLL',
    'DirectoryEntryExport': 'Presence of export table',
    'ImageDirectoryEntryExport': 'Size of export directory',
    'CheckSum': 'Checksum of the file',
    'DirectoryEntryImportSize': 'Size of import directory',
    'SectionMaxChar': 'Highest section characteristics value',
    'MajorImageVersion': 'Major version of the executable',
    'AddressOfEntryPoint': 'Entry point relative to image base',
    'SectionMinEntropy': 'Minimum entropy among all sections',
    'SizeOfHeaders': 'Size of headers in bytes',
    'SectionMinVirtualsize': 'Minimum virtual size among all sections'
}

# SHAP explainer
_EXPLAINER = None

# --- Load the Model on Module Import ---
try:
    if os.path.exists(MODEL_PATH):
        _ML_MODEL = joblib.load(MODEL_PATH)
        # Initialize SHAP explainer if model is loaded successfully
        if _ML_MODEL is not None:
            try:
                # Use the appropriate explainer based on the model type
                if hasattr(_ML_MODEL, 'feature_importances_'):  # For tree-based models
                    _EXPLAINER = shap.TreeExplainer(_ML_MODEL)
                else:  # For other models
                    _EXPLAINER = shap.Explainer(_ML_MODEL)
                print("SHAP explainer initialized successfully")
            except Exception as shap_err:
                print(f"Warning: SHAP explainer initialization failed: {shap_err}")
                _EXPLAINER = None
        print(f"Successfully loaded ML model from {MODEL_PATH}")
    else:
        print(f"Warning: ML model file not found at {MODEL_PATH}. ML prediction will be disabled.")
        _ML_MODEL = None
        _EXPLAINER = None
except Exception as e:
    print(f"Error loading ML model: {e}")
    traceback.print_exc()
    _ML_MODEL = None
    _EXPLAINER = None

# --- Helper Functions (Internal) ---
def _calculate_entropy(data):
    """Calculates the Shannon entropy of a byte string."""
    if not data or not isinstance(data, (bytes, bytearray)):
        return 0
    entropy = 0
    data_len = len(data)
    byte_counts = {} # Use dict for potentially faster counts

    for byte_val in data:
        byte_counts[byte_val] = byte_counts.get(byte_val, 0) + 1

    for count in byte_counts.values():
        p_x = float(count) / data_len
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)

    return entropy

def _extract_features(file_path):
    """Extracts PE features relevant for the ML model."""
    try:
        pe = pefile.PE(file_path, fast_load=True)

        features = {
            'MajorLinkerVersion': getattr(pe.OPTIONAL_HEADER, 'MajorLinkerVersion', 0),
            'MinorOperatingSystemVersion': getattr(pe.OPTIONAL_HEADER, 'MinorOperatingSystemVersion', 0),
            'MajorSubsystemVersion': getattr(pe.OPTIONAL_HEADER, 'MajorSubsystemVersion', 0),
            'SizeOfStackReserve': getattr(pe.OPTIONAL_HEADER, 'SizeOfStackReserve', 0),
            'TimeDateStamp': getattr(pe.FILE_HEADER, 'TimeDateStamp', 0),
            'MajorOperatingSystemVersion': getattr(pe.OPTIONAL_HEADER, 'MajorOperatingSystemVersion', 0),
            'Characteristics': getattr(pe.FILE_HEADER, 'Characteristics', 0),
            'ImageBase': getattr(pe.OPTIONAL_HEADER, 'ImageBase', 0),
            'Subsystem': getattr(pe.OPTIONAL_HEADER, 'Subsystem', 0),
            'MinorImageVersion': getattr(pe.OPTIONAL_HEADER, 'MinorImageVersion', 0),
            'MinorSubsystemVersion': getattr(pe.OPTIONAL_HEADER, 'MinorSubsystemVersion', 0),
            'SizeOfInitializedData': getattr(pe.OPTIONAL_HEADER, 'SizeOfInitializedData', 0),
            'DllCharacteristics': getattr(pe.OPTIONAL_HEADER, 'DllCharacteristics', 0),
            'DirectoryEntryExport': 1 if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT else 0,
            'CheckSum': getattr(pe.OPTIONAL_HEADER, 'CheckSum', 0),
            'MajorImageVersion': getattr(pe.OPTIONAL_HEADER, 'MajorImageVersion', 0),
            'AddressOfEntryPoint': getattr(pe.OPTIONAL_HEADER, 'AddressOfEntryPoint', 0),
            'SizeOfHeaders': getattr(pe.OPTIONAL_HEADER, 'SizeOfHeaders', 0),
            # Initialize potentially missing ones
            'ImageDirectoryEntryExport': 0,
            'DirectoryEntryImportSize': 0,
            'SectionMaxChar': 0,
            'SectionMinEntropy': 0.0,
            'SectionMinVirtualsize': 0
        }

        # Directory Entries - check existence carefully
        if features['DirectoryEntryExport'] > 0 and hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY') and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']:
            features['ImageDirectoryEntryExport'] = getattr(pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']], 'Size', 0)

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') and pe.DIRECTORY_ENTRY_IMPORT and hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY') and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']:
            features['DirectoryEntryImportSize'] = getattr(pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']], 'Size', 0)

        # Section-based features
        if hasattr(pe, 'sections') and pe.sections:
            entropies = []
            virtual_sizes = []
            characteristics = []
            for section in pe.sections:
                try:
                    data = section.get_data()
                    entropies.append(_calculate_entropy(data))
                    virtual_sizes.append(getattr(section, 'Misc_VirtualSize', 0))
                    characteristics.append(getattr(section, 'Characteristics', 0))
                except Exception:
                    # Handle error reading specific section data if necessary
                    pass # Or append default values

            if entropies:
                features['SectionMinEntropy'] = min(entropies) if entropies else 0.0
            if virtual_sizes:
                features['SectionMinVirtualsize'] = min(virtual_sizes) if virtual_sizes else 0
            if characteristics:
                 features['SectionMaxChar'] = max(characteristics) if characteristics else 0

        pe.close()

        # Create DataFrame with the specific required order
        return pd.DataFrame([features], columns=_FEATURE_ORDER)

    except pefile.PEFormatError:
        # Not a PE file, which is expected sometimes, return None
        return None
    except Exception as e:
        print(f"Error extracting PE features from {os.path.basename(file_path)}: {e}")
        traceback.print_exc()
        return None # Indicate feature extraction failure

def _get_feature_importances(features_df):
    """
    Calculate feature importances using SHAP values.
    
    Args:
        features_df: DataFrame with features
        
    Returns:
        List of dictionaries with feature name, importance, and description
    """
    if _EXPLAINER is None:
        return None
    
    try:
        # Get SHAP values
        shap_values = _EXPLAINER.shap_values(features_df)
        
        # Handle different SHAP value formats
        if isinstance(shap_values, list):
            # For tree models, typically returns a list where second element is for positive class
            values = shap_values[1] if len(shap_values) > 1 else shap_values[0]
        else:
            # For other models
            values = shap_values
            
        # Get absolute values and convert to numpy array if needed
        abs_values = np.abs(values)
        if isinstance(abs_values, list):
            abs_values = np.array(abs_values)
            
        # Extract the actual values (handling array shapes)
        if len(abs_values.shape) > 1:
            feature_importances = abs_values[0]
        else:
            feature_importances = abs_values
            
        # Create a list of dictionaries with feature importances
        importances = []
        for i, feature in enumerate(_FEATURE_ORDER):
            # Safely convert to float, handling arrays of any size
            imp_value = feature_importances[i]
            
            # Handle numpy arrays safely
            if hasattr(imp_value, 'shape'):
                # For multi-dimensional arrays, sum the values or take first element
                if imp_value.size > 1:
                    importance = float(np.sum(imp_value))
                else:
                    # For single values
                    importance = float(imp_value.flatten()[0])
            else:
                # For regular Python scalars
                importance = float(imp_value)
                
            importances.append({
                "feature": feature,
                "importance": importance,
                "description": _FEATURE_DESCRIPTIONS.get(feature, "No description available")
            })
            
        # Sort by importance (descending)
        importances.sort(key=lambda x: x["importance"], reverse=True)
        
        # Return top 10 features
        return importances[:10]
    except Exception as e:
        print(f"Error calculating feature importances: {e}")
        traceback.print_exc()
        return None

# --- Public Service Function ---
def analyze_pe_file(file_path):
    """
    Analyzes a given file path using the loaded PE malware detection model.

    Args:
        file_path (str): The path to the file to analyze.

    Returns:
        dict: A dictionary containing:
            - "prediction": "Malware", "Safe", "Not Applicable", etc.
            - "feature_importances": List of dictionaries with feature importances (if available)
    """
    filename = os.path.basename(file_path)
    file_ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    
    result = {
        "prediction": "Unknown",
        "feature_importances": None,
        "analysis_time": 0
    }

    if file_ext not in ALLOWED_ML_EXTENSIONS:
        result["prediction"] = "Not Applicable"
        return result

    if _ML_MODEL is None:
        print(f"ML model not loaded, skipping prediction for {filename}.")
        result["prediction"] = "ML Model Not Loaded"
        return result

    print(f"Running PE analysis for {filename}...")
    start_time = pd.Timestamp.now()
    features_df = _extract_features(file_path)

    if features_df is None:
        print(f"Feature extraction failed or not a PE file: {filename}")
        result["prediction"] = "Feature Extraction Error"
        return result

    try:
        if features_df.empty:
             print(f"Warning: Empty feature set generated for {filename}")
             result["prediction"] = "Feature Extraction Error"
             return result

        # Make prediction
        prediction = _ML_MODEL.predict(features_df)
        pred_result = "Malware" if prediction[0] == 1 else "Safe"
        print(f"ML Prediction for {filename}: {pred_result}")
        
        # Calculate feature importances
        if _EXPLAINER is not None:
            feature_importances = _get_feature_importances(features_df)
        else:
            print("SHAP explainer not available, skipping feature importance calculation")
            feature_importances = None
            
        end_time = pd.Timestamp.now()
        analysis_time = (end_time - start_time).total_seconds()
        
        # Set the result
        result["prediction"] = pred_result
        result["feature_importances"] = feature_importances
        result["analysis_time"] = round(analysis_time, 3)
        
        return result
    except Exception as ml_err:
        print(f"Error during ML prediction for {filename}: {ml_err}")
        traceback.print_exc()
        result["prediction"] = "ML Error"
        return result

