from oletools.olevba import VBA_Parser

# Automatically get the filename of the uploaded file
import os


def analyze_docx_for_macros(filename):

    # Run olevba analysis
    vba_parser = VBA_Parser(filename)

    if vba_parser.detect_vba_macros():
        
        for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
            return "Malicious"
        for kw_type, keyword, description in vba_parser.analyze_macros():
            return "Malicious"
        
        return "Benign"
    else:
        return "Benign"
