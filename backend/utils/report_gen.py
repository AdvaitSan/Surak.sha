def generate_report(file_info):
    """
    Generate a human-readable report from the processed file information.

    Parameters:
        file_info (dict): Processed file information as returned by process_file.

    Returns:
        str: A formatted report string.
    """
    if 'Error' in file_info:
        return f"Error processing file: {file_info['Error']}"

    report_lines = [
        "File Analysis Report:",
        f"MD5: {file_info.get('MD5', 'N/A')}",
        f"SHA1: {file_info.get('SHA1', 'N/A')}",
        f"SHA256: {file_info.get('SHA256', 'N/A')}",
        f"File Size: {file_info.get('Size', 'N/A')} bytes",
        f"File Type: {file_info.get('File Type', 'N/A')}",
        f"MIME Type: {file_info.get('MIME Type', 'N/A')}",
        f"Entropy: {file_info.get('Entropy', 'N/A'):.4f}"
    ]
    return "\n".join(report_lines)
