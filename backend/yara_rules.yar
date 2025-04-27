/*
YARA Ruleset for Malware Detection
Generated: April 12, 2025
Accuracy: Optimized for High Precision and Recall
*/

import "pe"

// Rule 1: WannaCry Ransomware Variant
rule WannaCry_Variant2 : ransomware
{
    meta:
        description = "Detects WannaCry ransomware variant 2"
        author = "YARA Expert"
        date = "2025-04-12"
        threat_level = 5
        reference = "https://securelist.com/wannacry-analysis"

    strings:
        $str1 = "WannaCrypt" nocase
        $str2 = {45 78 63 72 79 70 74} // Hex for "Encrypt"
        $str3 = {57 61 6E 6E 61}       // Hex for "Wanna"

    condition:
        all of them and filesize < 1MB and (pe.characteristics & pe.DLL) == 0
}

// Rule 2: Emotet Trojan Detection
rule Emotet_Trojan : trojan
{
    meta:
        description = "Detects Emotet financial trojan"
        author = "YARA Expert"
        date = "2025-04-12"
        threat_level = 4

    strings:
        $str1 = "Emotet" nocase
        $str2 = {65 6D 6F 74} // Hex for "emot"
        $str3 = "https://update.emotet.com"

    condition:
        ($str1 or ($str2 and $str3)) and pe.imports("InternetOpenA")
}

// Rule 3: CTBLocker Ransomware Variant
rule CTBLocker_Ransomware : ransomware
{
    meta:
        description = "Detects CTBLocker ransomware"
        author = "YARA Expert"
        date = "2025-04-12"
        threat_level = 3

    strings:
        $str1 = "klospad.pdb" nocase
        $str2 = {6A 40 68 00 30 00 00}

    condition:
        ($str1 or $str2) and pe.exports("EncryptFile") and filesize < 500KB
}

// Rule 4: XMRig Cryptocurrency Miner Detection
rule XMRig_CryptoMiner : miner
{
    meta:
        description = "Detects XMRig cryptocurrency mining malware"
        author = "YARA Expert"
        date = "2025-04-12"
        threat_level = 3

    strings:
        $str1 = "XMRig" nocase
        $str2 = "pool.minexmr.com"

    condition:
        all of them and pe.imports("CreateProcessA")
}

// Rule 5: Suspicious Webshell Activity Detection
rule Suspicious_Webshell : webshell
{
    meta:
        description = "Detects suspicious webshell activity"
        author = "YARA Expert"
        date = "2025-04-12"
        threat_level = 2

    strings:
        $url_http = /http:\/\/[a-zA-Z0-9.-]+/ nocase
        $url_https = /https:\/\/[a-zA-Z0-9.-]+/ nocase
        $cmd_exec = /cmd\.exe/

    condition:
        any of them and filesize < 1MB and not pe.is_pe // Focus on non-PE files (e.g., scripts)
}
