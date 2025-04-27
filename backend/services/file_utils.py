# backend/services/file_utils.py

import os
import mimetypes
import platform

def get_file_mime_type(file_path):
    """
    Detect the MIME type of a file, with robust platform-specific handling.
    
    Args:
        file_path (str): Path to the file
        
    Returns:
        dict: Dictionary with mime_type and mime_category
    """
    # Initialize mimetypes database
    if not mimetypes.inited:
        mimetypes.init()
    
    # Get file extension
    _, file_extension = os.path.splitext(file_path)
    file_extension = file_extension.lower()
    
    # Only try to use magic on non-Windows systems or if explicitly enabled
    use_magic = os.environ.get('FORCE_USE_MAGIC', 'false').lower() == 'true'
    is_windows = platform.system().lower() == 'windows'
    
    if not is_windows or use_magic:
        try:
            # Try to use magic for more accurate detection
            import magic
            mime = magic.Magic(mime=True)
            mime_type = mime.from_file(file_path)
            
            # Extract general category from the MIME type
            mime_category = mime_type.split('/')[0] if '/' in mime_type else 'unknown'
            
            # Get a more specific description
            mime_description = magic.Magic().from_file(file_path)
            
            return {
                "mime_type": mime_type,
                "mime_category": mime_category,
                "mime_description": mime_description
            }
        except Exception as e:
            print(f"Error detecting MIME type with python-magic: {e}")
            # Fall through to fallback methods
    else:
        print("Skipping python-magic on Windows platform, using fallback detection")
    
    # Fallback methods - use mimetypes library first
    mime_type, _ = mimetypes.guess_type(file_path)
    
    # If that fails, use extension-based detection
    if not mime_type:
        # Common executable types
        if file_extension in ['.exe', '.dll', '.sys']:
            mime_type = 'application/x-msdownload'
            mime_category = 'application'
            mime_description = f"Windows {file_extension[1:].upper()} executable"
        elif file_extension in ['.pdf']:
            mime_type = 'application/pdf'
            mime_category = 'application'
            mime_description = 'PDF document'
        elif file_extension in ['.doc', '.docx']:
            mime_type = 'application/msword'
            mime_category = 'application'
            mime_description = 'Microsoft Word document'
        elif file_extension in ['.txt']:
            mime_type = 'text/plain'
            mime_category = 'text'
            mime_description = 'Plain text file'
        elif file_extension in ['.html', '.htm']:
            mime_type = 'text/html'
            mime_category = 'text'
            mime_description = 'HTML document'
        else:
            mime_type = 'application/octet-stream'
            mime_category = 'application'
            mime_description = 'Binary data'
    else:
        mime_category = mime_type.split('/')[0] if '/' in mime_type else 'unknown'
        mime_description = f"{mime_category.capitalize()} data"
        
    return {
        "mime_type": mime_type or "application/octet-stream",
        "mime_category": mime_category,
        "mime_description": mime_description
    } 