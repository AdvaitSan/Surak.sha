"""
BAT File Analyzer
----------------
This module provides batch file analysis capabilities for detecting potentially
malicious Windows batch (.bat) files. Rather than using ML models, this analyzer 
uses rule-based heuristics to identify suspicious patterns and dangerous commands 
commonly found in malicious batch scripts.

Detection mechanisms:
1. Dangerous commands - Identifies commands that can be used maliciously
2. Suspicious patterns - Looks for obfuscation, encoding, and evasion techniques
3. Command chaining - Detects complex command chaining often used to hide malicious intent
4. Unusual behaviors - Identifies unusual behaviors like file deletion, disabling security tools
5. Obfuscation scoring - Analyzes the level of obfuscation used in the script
"""

import os
import re
import math
import time
from collections import Counter

# --- Constants and Configuration ---
# Commands that are commonly used in malicious batch files
DANGEROUS_COMMANDS = {
    'powershell': r'\b(powershell|powershell\.exe)\b',
    'del': r'\b(del|erase)\b',
    'rmdir': r'\b(rmdir|rd)\b',
    'reg': r'\b(reg\.exe|reg|regedit)\b',
    'netsh': r'\b(netsh|netsh\.exe)\b',
    'taskkill': r'\b(taskkill|taskkill\.exe)\b',
    'sc': r'\bsc\s+(stop|config|delete)\b',
    'net': r'\bnet\s+(stop|user|localgroup)\b',
    'attrib': r'\battrib\b',
    'vssadmin': r'\bvssadmin\s+delete\b',
    'cipher': r'\bcipher\s+\/w\b',  # Secure deletion
    'wmic': r'\bwmic\b',
    'bitsadmin': r'\bbitsadmin\b',
    'certutil': r'\bcertutil\b',  # Often used for downloading files
    'schtasks': r'\bschtasks\b',
    'wevtutil': r'\bwevtutil\s+cl\b',  # Clear event logs
}

# Suspicious patterns often found in malicious scripts
SUSPICIOUS_PATTERNS = {
    'base64_encoded': r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
    'hex_encoded': r'(%[0-9A-Fa-f]{2}){3,}',
    'echo_piping': r'echo.+\|\s*([a-zA-Z]+)',
    'obfuscated_var': r'\%[a-zA-Z0-9_]+\:~[0-9]+,[0-9]+\%',
    'strange_chars': r'(\^|%|\$\{|\^@|\^\$|\^\^)',
    'hidden_extension': r'\.(bat|cmd|exe)\s*\.\s*[a-z]{3,4}',
    'command_separator_abuse': r'(\&\&|\|\||;)\s*(?=\w)',
    'self_delete': r'del\s+.*%0',
    'disable_defender': r'Set-MpPreference\s+-DisableRealtimeMonitoring',
    'disable_firewall': r'netsh\s+firewall\s+set\s+opmode\s+disable',
    'create_user': r'net\s+user\s+.+\s+\/add',
    'download_execution': r'(curl|wget|certutil|bitsadmin).+\|\s*(cmd|powershell|sh|bash)',
    'registry_autorun': r'reg\s+add\s+.*\\Run',
    'uac_bypass': r'reg\s+add\s+.*\\Policies\\System',
    'temporary_file_creation': r'>\s*%temp%',
    'call_with_params': r'call\s+:[-_a-zA-Z0-9]+\s+.*',
    'eval_equivalent': r'(for\s+/f|call\s+set)'
}

def analyze_bat_file(file_path):
    """
    Analyzes a batch file for potential malicious content.
    
    Args:
        file_path: Path to the batch file
        
    Returns:
        A dictionary containing analysis results including:
        - prediction: "Malware" or "Clean"
        - risk_score: A float between 0.0 and 1.0
        - dangerous_commands: List of dangerous commands found
        - suspicious_patterns: List of suspicious patterns detected
        - obfuscation_score: Measure of obfuscation techniques
        - analysis_time: Time taken for analysis
    """
    start_time = time.time()
    
    try:
        # Check if file exists and is accessible
        if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
            return {
                "error": f"File not found or not accessible: {file_path}",
                "prediction": "Error",
                "risk_score": 0.0,
                "analysis_time": time.time() - start_time
            }
        
        # Read the file content
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
        
        # Initialize counters and results
        dangerous_cmds_found = []
        suspicious_patterns_found = []
        cmd_count = 0
        obfuscation_indicators = 0
        uncommon_chars_count = 0
        line_continuations = 0
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip empty lines or comments
            if not line or line.startswith('::') or line.startswith('REM '):
                continue
            
            # Check for dangerous commands
            for cmd_name, pattern in DANGEROUS_COMMANDS.items():
                if re.search(pattern, line, re.IGNORECASE):
                    dangerous_cmds_found.append({
                        "command": cmd_name, 
                        "line": line_num,
                        "content": line[:50] + ('...' if len(line) > 50 else '')
                    })
                    cmd_count += 1
            
            # Check for suspicious patterns
            for pattern_name, pattern in SUSPICIOUS_PATTERNS.items():
                matches = re.findall(pattern, line, re.IGNORECASE)
                if matches:
                    suspicious_patterns_found.append({
                        "pattern": pattern_name,
                        "matches": len(matches),
                        "line": line_num
                    })
                    
                    # Patterns that strongly indicate obfuscation
                    if pattern_name in ['base64_encoded', 'hex_encoded', 'obfuscated_var', 
                                      'strange_chars', 'echo_piping']:
                        obfuscation_indicators += len(matches)
            
            # Count line continuations (^)
            if line.rstrip().endswith('^'):
                line_continuations += 1
            
            # Count uncommon characters often used in obfuscation
            uncommon_chars = re.findall(r'[\^%!~`]', line)
            uncommon_chars_count += len(uncommon_chars)
        
        # Calculate risk score based on findings
        dangerous_cmd_score = min(1.0, len(dangerous_cmds_found) / 10.0)
        suspicious_pattern_score = min(1.0, len(suspicious_patterns_found) / 15.0)
        
        # Calculate obfuscation score
        total_lines = len([l for l in lines if l.strip() and not l.strip().startswith(('::', 'REM'))])
        obfuscation_score = 0.0
        if total_lines > 0:
            # Normalize obfuscation indicators
            obfuscation_score = min(1.0, (obfuscation_indicators + line_continuations + 
                                        (uncommon_chars_count / total_lines)) / 20.0)
        
        # Calculate overall risk score (weighted average)
        risk_score = (dangerous_cmd_score * 0.4 + 
                     suspicious_pattern_score * 0.4 + 
                     obfuscation_score * 0.2)
        
        # Determine prediction
        prediction = "Malware" if risk_score > 0.5 else "Clean"
        
        # Create detailed report
        return {
            "prediction": prediction,
            "risk_score": risk_score,
            "dangerous_commands": dangerous_cmds_found[:10],  # Limit to top 10
            "suspicious_patterns": suspicious_patterns_found[:10],  # Limit to top 10
            "obfuscation_score": obfuscation_score,
            "analysis_time": time.time() - start_time
        }
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {
            "error": str(e),
            "prediction": "Error",
            "risk_score": 0.0,
            "analysis_time": time.time() - start_time
        }

def get_bat_characteristics(file_path):
    """
    Gets detailed characteristics of a batch file for more in-depth analysis.
    This function can be used to supplement the main analysis with additional insights.
    
    Args:
        file_path: Path to the batch file
        
    Returns:
        A dictionary with detailed characteristics
    """
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
        
        # Count different types of commands
        command_types = {
            'file_operations': 0,  # copy, del, move, etc.
            'network_operations': 0,  # ping, net, etc.
            'system_operations': 0,  # shutdown, taskkill, etc.
            'registry_operations': 0,  # reg
            'other_commands': 0
        }
        
        # Analyze script structure
        labels = 0
        goto_statements = 0
        if_statements = 0
        for_loops = 0
        call_statements = 0
        
        for line in lines:
            line = line.strip().lower()
            
            # Skip empty lines or comments
            if not line or line.startswith('::') or line.startswith('rem '):
                continue
            
            # Count command types
            if any(cmd in line for cmd in ['copy', 'xcopy', 'move', 'del', 'erase', 'mkdir', 'rmdir']):
                command_types['file_operations'] += 1
            elif any(cmd in line for cmd in ['ping', 'net ', 'netsh', 'ipconfig', 'curl', 'wget']):
                command_types['network_operations'] += 1
            elif any(cmd in line for cmd in ['shutdown', 'taskkill', 'tasklist', 'sc ', 'wmic']):
                command_types['system_operations'] += 1
            elif 'reg ' in line:
                command_types['registry_operations'] += 1
            else:
                command_types['other_commands'] += 1
            
            # Count script structure elements
            if re.match(r'^:[a-zA-Z0-9_-]+\s*$', line):
                labels += 1
            if 'goto ' in line:
                goto_statements += 1
            if line.startswith('if '):
                if_statements += 1
            if line.startswith('for '):
                for_loops += 1
            if line.startswith('call '):
                call_statements += 1
        
        return {
            'command_types': command_types,
            'script_structure': {
                'labels': labels,
                'goto_statements': goto_statements,
                'if_statements': if_statements,
                'for_loops': for_loops,
                'call_statements': call_statements,
                'total_lines': len(lines),
                'code_lines': len([l for l in lines if l.strip() and not (l.strip().startswith('::') or l.strip().startswith('rem '))])
            }
        }
    except Exception as e:
        return {'error': str(e)} 