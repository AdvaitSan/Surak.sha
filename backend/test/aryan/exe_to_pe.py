import joblib
import pefile
import pandas as pd
import numpy as np
import math
import os
import argparse # For command-line arguments

# --- Step 1: Define ALL Features Extractable by the Function ---
# This list should contain all 54 features your extract_pe_features provides.
extractable_features = [
    'Machine', 'SizeOfOptionalHeader', 'Characteristics', 'MajorLinkerVersion',
    'MinorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData',
    'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode',
    'BaseOfData', 'ImageBase', 'SectionAlignment', 'FileAlignment',
    'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion',
    'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion',
    'MinorSubsystemVersion', 'SizeOfImage', 'SizeOfHeaders', 'CheckSum',
    'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve',
    'SizeOfStackCommit', 'SizeOfHeapReserve', 'SizeOfHeapCommit',
    'LoaderFlags', 'NumberOfRvaAndSizes', 'SectionsNb',
    'SectionsMeanEntropy', 'SectionsMinEntropy', 'SectionsMaxEntropy',
    'SectionsMeanRawsize', 'SectionsMinRawsize', 'SectionMaxRawsize',
    'SectionsMeanVirtualsize', 'SectionsMinVirtualsize', 'SectionMaxVirtualsize',
    'ImportsNbDLL', 'ImportsNb', 'ImportsNbOrdinal', 'ExportNb',
    'ResourcesNb', 'ResourcesMeanEntropy', 'ResourcesMinEntropy',
    'ResourcesMaxEntropy', 'ResourcesMeanSize', 'ResourcesMinSize',
    'ResourcesMaxSize', 'LoadConfigurationSize', 'VersionInformationSize'
]

# --- Step 2: Define the EXACT 14 Features the MODEL Expects ---
# Updated based on the user's provided list from notebook analysis
selected_feature_names_for_model = [
    'DllCharacteristics',
    'Machine',
    'Characteristics',
    'VersionInformationSize',
    'ImageBase',
    'SectionsMaxEntropy',
    'SizeOfOptionalHeader',
    'Subsystem',
    'MajorSubsystemVersion',
    'ResourcesMinEntropy',
    'ResourcesMaxEntropy',
    'SectionsMeanEntropy',
    'SectionsMinEntropy',
    'MajorOperatingSystemVersion'
]

# Verify the count
if len(selected_feature_names_for_model) != 14:
    print(f"FATAL ERROR: Expected 14 features for the model, but found {len(selected_feature_names_for_model)}.")
    print("Please double-check the 'selected_feature_names_for_model' list against your notebook output.")
    exit(1) # Exit if the count is wrong


# --- Step 3: Feature Extraction Functions (Keep as before) ---
def calculate_entropy(data):
    """Calculate the entropy of a byte string."""
    if not data:
        return 0
    entropy = 0
    if len(data) == 0:
        return 0.0
    byte_counts = np.zeros(256, dtype=np.float64)
    for byte in data:
        byte_counts[byte] += 1
    probabilities = byte_counts / len(data)
    for p in probabilities:
        if p > 0:
            entropy -= p * math.log(p, 2)
    return entropy

def extract_pe_features(file_path, feature_list_to_extract):
    """Extracts PE features specified in feature_list_to_extract."""
    features = {}
    try:
        pe = pefile.PE(file_path, fast_load=True)

        # Extract features, ensuring we get at least the ones needed for the model
        # (Using 'get' with default 0 for safety, although the final check handles it too)

        # --- PE Header Features ---
        features['Machine'] = getattr(pe.FILE_HEADER, 'Machine', 0)
        features['SizeOfOptionalHeader'] = getattr(pe.FILE_HEADER, 'SizeOfOptionalHeader', 0)
        features['Characteristics'] = getattr(pe.FILE_HEADER, 'Characteristics', 0)

        # --- Optional Header Features ---
        # Check if OPTIONAL_HEADER exists before accessing its attributes
        if hasattr(pe, 'OPTIONAL_HEADER'):
            opt_header = pe.OPTIONAL_HEADER
            features['MajorLinkerVersion'] = getattr(opt_header, 'MajorLinkerVersion', 0)
            features['MinorLinkerVersion'] = getattr(opt_header, 'MinorLinkerVersion', 0)
            features['SizeOfCode'] = getattr(opt_header, 'SizeOfCode', 0)
            features['SizeOfInitializedData'] = getattr(opt_header, 'SizeOfInitializedData', 0)
            features['SizeOfUninitializedData'] = getattr(opt_header, 'SizeOfUninitializedData', 0)
            features['AddressOfEntryPoint'] = getattr(opt_header, 'AddressOfEntryPoint', 0)
            features['BaseOfCode'] = getattr(opt_header, 'BaseOfCode', 0)
            features['BaseOfData'] = getattr(opt_header, 'BaseOfData', 0) # Handle missing BaseOfData in 64-bit
            features['ImageBase'] = getattr(opt_header, 'ImageBase', 0)
            features['SectionAlignment'] = getattr(opt_header, 'SectionAlignment', 0)
            features['FileAlignment'] = getattr(opt_header, 'FileAlignment', 0)
            features['MajorOperatingSystemVersion'] = getattr(opt_header, 'MajorOperatingSystemVersion', 0)
            features['MinorOperatingSystemVersion'] = getattr(opt_header, 'MinorOperatingSystemVersion', 0)
            features['MajorImageVersion'] = getattr(opt_header, 'MajorImageVersion', 0)
            features['MinorImageVersion'] = getattr(opt_header, 'MinorImageVersion', 0)
            features['MajorSubsystemVersion'] = getattr(opt_header, 'MajorSubsystemVersion', 0)
            features['MinorSubsystemVersion'] = getattr(opt_header, 'MinorSubsystemVersion', 0)
            features['SizeOfImage'] = getattr(opt_header, 'SizeOfImage', 0)
            features['SizeOfHeaders'] = getattr(opt_header, 'SizeOfHeaders', 0)
            features['CheckSum'] = getattr(opt_header, 'CheckSum', 0)
            features['Subsystem'] = getattr(opt_header, 'Subsystem', 0)
            features['DllCharacteristics'] = getattr(opt_header, 'DllCharacteristics', 0)
            features['SizeOfStackReserve'] = getattr(opt_header, 'SizeOfStackReserve', 0)
            features['SizeOfStackCommit'] = getattr(opt_header, 'SizeOfStackCommit', 0)
            features['SizeOfHeapReserve'] = getattr(opt_header, 'SizeOfHeapReserve', 0)
            features['SizeOfHeapCommit'] = getattr(opt_header, 'SizeOfHeapCommit', 0)
            features['LoaderFlags'] = getattr(opt_header, 'LoaderFlags', 0)
            features['NumberOfRvaAndSizes'] = getattr(opt_header, 'NumberOfRvaAndSizes', 0)
        else:
            # If no optional header, set related features to 0
            opt_header_keys = [k for k in feature_list_to_extract if k not in ['Machine', 'SizeOfOptionalHeader', 'Characteristics']]
            for k in opt_header_keys:
                 # Set default only if it wasn't potentially set by other sections below (e.g., section/resource/import features)
                 if k not in features:
                     features[k] = 0.0


        # --- Section Features ---
        sections = getattr(pe, 'sections', [])
        features['SectionsNb'] = len(sections)

        section_features_defaults = {
            'SectionsMeanEntropy': 0.0, 'SectionsMinEntropy': 0.0, 'SectionsMaxEntropy': 0.0,
            'SectionsMeanRawsize': 0.0, 'SectionsMinRawsize': 0.0, 'SectionMaxRawsize': 0.0,
            'SectionsMeanVirtualsize': 0.0, 'SectionsMinVirtualsize': 0.0, 'SectionMaxVirtualsize': 0.0
        }

        if features['SectionsNb'] > 0:
            # Use try-except blocks for individual calculations for robustness
            try: entropies = [s.get_entropy() for s in sections]
            except Exception: entropies = []

            try: raw_sizes = [s.SizeOfRawData for s in sections]
            except Exception: raw_sizes = []

            try: virtual_sizes = [s.Misc_VirtualSize for s in sections]
            except Exception: virtual_sizes = []

            features['SectionsMeanEntropy'] = np.mean(entropies) if entropies else 0.0
            features['SectionsMinEntropy'] = np.min(entropies) if entropies else 0.0
            features['SectionsMaxEntropy'] = np.max(entropies) if entropies else 0.0
            features['SectionsMeanRawsize'] = np.mean(raw_sizes) if raw_sizes else 0.0
            features['SectionsMinRawsize'] = np.min(raw_sizes) if raw_sizes else 0.0
            features['SectionMaxRawsize'] = np.max(raw_sizes) if raw_sizes else 0.0
            features['SectionsMeanVirtualsize'] = np.mean(virtual_sizes) if virtual_sizes else 0.0
            features['SectionsMinVirtualsize'] = np.min(virtual_sizes) if virtual_sizes else 0.0
            features['SectionMaxVirtualsize'] = np.max(virtual_sizes) if virtual_sizes else 0.0
        else:
            features.update(section_features_defaults)

        # --- Import Features ---
        features['ImportsNbDLL'] = 0
        features['ImportsNb'] = 0
        features['ImportsNbOrdinal'] = 0
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                features['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
                imports_count = 0
                imports_ordinal_count = 0
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    imports_count += len(entry.imports)
                    for imp in entry.imports:
                        if getattr(imp, 'import_by_ordinal', False) is True:
                            imports_ordinal_count += 1
                features['ImportsNb'] = imports_count
                features['ImportsNbOrdinal'] = imports_ordinal_count
        except Exception: # Handle cases where import directory is missing/malformed
            pass # Keep defaults (0)

        # --- Export Features ---
        features['ExportNb'] = 0
        try:
             pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
             if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                  features['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        except Exception:
            pass # Keep default (0)

        # --- Resource Features ---
        features['ResourcesNb'] = 0
        resource_features_defaults = {
            'ResourcesMeanEntropy': 0.0, 'ResourcesMinEntropy': 0.0, 'ResourcesMaxEntropy': 0.0,
            'ResourcesMeanSize': 0.0, 'ResourcesMinSize': 0.0, 'ResourcesMaxSize': 0.0
        }
        resources = []
        try:
            # Ensure resources directory is parsed only if needed features are requested
            resource_related_features = [f for f in feature_list_to_extract if 'Resource' in f]
            if resource_related_features:
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
                if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                        if hasattr(resource_type, 'directory'):
                            for resource_id in resource_type.directory.entries:
                                if hasattr(resource_id, 'directory'):
                                    for resource_lang in resource_id.directory.entries:
                                        if (hasattr(resource_lang, 'data') and
                                            hasattr(resource_lang.data, 'struct') and
                                            hasattr(resource_lang.data.struct, 'Size') and
                                            hasattr(resource_lang.data.struct, 'OffsetToData')):
                                            data_rva = resource_lang.data.struct.OffsetToData
                                            size = resource_lang.data.struct.Size
                                            data = pe.get_data(data_rva, size)
                                            resources.append({'size': size, 'entropy': calculate_entropy(data)})
                                        else: pass
                    features['ResourcesNb'] = len(resources)
                    if features['ResourcesNb'] > 0:
                        entropies = [r['entropy'] for r in resources]
                        sizes = [r['size'] for r in resources]
                        features['ResourcesMeanEntropy'] = np.mean(entropies) if entropies else 0.0
                        features['ResourcesMinEntropy'] = np.min(entropies) if entropies else 0.0
                        features['ResourcesMaxEntropy'] = np.max(entropies) if entropies else 0.0
                        features['ResourcesMeanSize'] = np.mean(sizes) if sizes else 0.0
                        features['ResourcesMinSize'] = np.min(sizes) if sizes else 0.0
                        features['ResourcesMaxSize'] = np.max(sizes) if sizes else 0.0
                    else:
                        features.update(resource_features_defaults)
                else:
                     features.update(resource_features_defaults)
            else: # If no resource features needed, set defaults
                features.update(resource_features_defaults)

        except Exception:
             features.update(resource_features_defaults) # Default on error


        # --- Load Configuration Size ---
        features['LoadConfigurationSize'] = 0
        try:
            if 'LoadConfigurationSize' in feature_list_to_extract:
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']])
                if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG') and hasattr(pe.DIRECTORY_ENTRY_LOAD_CONFIG, 'struct') and hasattr(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct, 'Size'):
                    features['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
        except Exception:
            pass # Keep default 0

        # --- Version Information Size ---
        features['VersionInformationSize'] = 0
        try:
            if 'VersionInformationSize' in feature_list_to_extract:
                # Version info often depends on resources being parsed first
                if 'ResourcesNb' not in features:
                     pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])

                if hasattr(pe, 'VS_VERSIONINFO') and hasattr(pe, 'VS_FIXEDFILEINFO'):
                     if pe.VS_FIXEDFILEINFO:
                         if isinstance(pe.VS_FIXEDFILEINFO, list) and len(pe.VS_FIXEDFILEINFO) > 0:
                             fixed_info = pe.VS_FIXEDFILEINFO[0]
                             if hasattr(fixed_info, 'dwLength'): features['VersionInformationSize'] = fixed_info.dwLength
                             else: features['VersionInformationSize'] = 16
                         elif hasattr(pe.VS_FIXEDFILEINFO, 'dwLength'):
                              features['VersionInformationSize'] = pe.VS_FIXEDFILEINFO.dwLength
                         else: features['VersionInformationSize'] = 16
        except Exception:
            pass # Keep default 0

        pe.close()

        # --- Final Check: Ensure all required features are present ---
        # Add missing features with a default value of 0.0
        final_extracted = {}
        for f_name in feature_list_to_extract: # Check against the list passed to the function
            final_extracted[f_name] = features.get(f_name, 0.0)

        return final_extracted

    except pefile.PEFormatError as e:
        print(f"Error: Not a valid PE file or error parsing {file_path}: {e}")
        return None
    except MemoryError:
         print(f"Error: Memory Error processing {file_path}. File might be too large or corrupt.")
         return None
    except Exception as e:
        # Catching generic Exception to handle unexpected pefile issues
        print(f"An unexpected error occurred processing '{file_path}': {e}")
        # import traceback
        # traceback.print_exc() # Uncomment for detailed debug info
        return None


# --- Step 4: Prediction Function (Uses the 14 selected features) ---
def predict_exe_malware(file_path, model, full_feature_list, final_model_feature_list):
    """Predicts if an exe file is malware using the loaded model and correct features."""

    print(f"\n[+] Extracting features from: {os.path.basename(file_path)}")
    # Extract all potentially available features defined in full_feature_list
    extracted_features = extract_pe_features(file_path, full_feature_list)

    if extracted_features is None:
        return "Error: Could not extract features from the file."

    # Convert *all* extracted features to DataFrame first
    try:
        features_df_full = pd.DataFrame([extracted_features])
        # Ensure columns are in the order of extraction list initially
        # This step might not be strictly necessary if we select by name later, but good practice
        features_df_full = features_df_full[full_feature_list]
    except KeyError as e:
        print(f"\nError: Feature mismatch during *initial* DataFrame creation: {e}")
        print("This likely means a feature in 'extractable_features' was not produced by 'extract_pe_features'.")
        return "Error: Feature mismatch during data preparation (extraction)."
    except Exception as e:
        print(f"\nError creating full DataFrame for prediction: {e}")
        return "Error: Data formatting error before prediction."

    # Handle potential NaN/Infinite values in the full DataFrame
    features_df_full.replace([np.inf, -np.inf], np.nan, inplace=True)
    features_df_full.fillna(0, inplace=True) # Replace NaNs with 0

    # --- Select only the features the model was trained on ---
    try:
        # Select columns based on the final_model_feature_list
        features_df_final = features_df_full[final_model_feature_list]
        print(f"[+] Selected {len(final_model_feature_list)} features for the model.")
    except KeyError as e:
         print(f"\nError: One of the required {len(final_model_feature_list)} model features is missing after extraction: {e}")
         print("Please ensure the extraction function provides all features in 'selected_feature_names_for_model'.")
         print("Available columns after extraction:", features_df_full.columns.tolist())
         return "Error: Missing required feature for model input."
    except Exception as e:
        print(f"\nError selecting final features: {e}")
        return "Error: Failed to filter features for the model."

    # Now predict using the DataFrame with the correct 14 features
    print("[+] Features selected. Predicting...")
    try:
        # Important: Pass the DataFrame with the selected 14 features
        prediction = model.predict(features_df_final)
        probability = model.predict_proba(features_df_final)
        print("prediction: ", prediction)
        print("probability: ", probability)

        result_label = "Malware" if prediction[0] == 1 else "Legitimate"
        confidence = probability[0][1] if prediction[0] == 1 else probability[0][0]

        print(f"[+] Prediction: {result_label}")
        print(f"[+] Confidence: {confidence:.2%}") # Format as percentage

        return f"Result: The file is predicted to be {result_label} (Confidence: {confidence:.2%})"

    except ValueError as ve:
         print(f"\nError during model prediction (ValueError): {ve}")
         print(f"Model expected a certain number of features, but received {features_df_final.shape[1]}.")
         print("Ensure the model was trained on features: ", final_model_feature_list)
         print("Features passed to model:", features_df_final.columns.tolist())
         return "Error: Feature number mismatch during prediction."
    except Exception as e:
        print(f"\nError during model prediction: {e}")
        # Optional: print features for debugging
        # print("Features passed to model for prediction:\n", features_df_final)
        return "Error: Could not get prediction from the model."

# --- Step 5: Main Execution Block ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Predict if a .exe file is malware using a trained Random Forest model.")
    parser.add_argument("exe_path", help="Path to the .exe file to analyze.")
    parser.add_argument("-m", "--model_path", required=True, help="Path to the saved .joblib model file.")

    args = parser.parse_args()

    model_file = args.model_path
    exe_file = args.exe_path

    # --- Load the Model ---
    print(f"[+] Loading model from: {model_file}")
    if not os.path.exists(model_file):
        print(f"Error: Model file not found at '{model_file}'")
        exit(1)
    try:
        rf_model = joblib.load(model_file)
        print("[+] Model loaded successfully.")
        # Check how many features the loaded model expects
        model_expected_features = -1
        if hasattr(rf_model, 'n_features_in_'):
            model_expected_features = rf_model.n_features_in_
            print(f"[+] Loaded model expects {model_expected_features} features.")
            if model_expected_features != len(selected_feature_names_for_model):
                 print(f"FATAL WARNING: Model expects {model_expected_features} features, but script is configured to provide {len(selected_feature_names_for_model)}.")
                 print("Ensure 'selected_feature_names_for_model' list is absolutely correct!")
                 # exit(1) # Optional: Exit if mismatch detected
            else:
                 print("[+] Feature count matches expected by model.")
        else:
            print("[!] Could not automatically determine number of features expected by the loaded model.")

    except Exception as e:
        print(f"Error: Failed to load the model from '{model_file}': {e}")
        exit(1)

    # --- Check EXE File ---
    if not os.path.exists(exe_file):
        print(f"Error: Input .exe file not found at '{exe_file}'")
        exit(1)
    if not os.path.isfile(exe_file):
         print(f"Error: The provided path '{exe_file}' is not a file.")
         exit(1)


    # --- Perform Prediction ---
    # Pass the model, the list of all extractable features, AND the final 14 features
    final_result = predict_exe_malware(
        exe_file,
        rf_model,
        extractable_features,             # List of all features to attempt extraction
        selected_feature_names_for_model  # List of the 14 features model needs
    )

    print("\n----------------------------------------")
    print(f"Analysis Report for: {os.path.basename(exe_file)}")
    print(final_result)
    print("----------------------------------------")
