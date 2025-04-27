@echo off
:: This is a benign batch file for system maintenance
:: This file demonstrates legitimate usage patterns

title System Maintenance Utility
echo ===================================
echo        System Maintenance Tool
echo ===================================
echo.

:: Create backup folder if it doesn't exist
if not exist "%USERPROFILE%\Backups" (
    echo Creating backup directory...
    mkdir "%USERPROFILE%\Backups"
) else (
    echo Backup directory already exists.
)

:: Get current date for backup folder naming
for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set "dt=%%a"
set "YYYY=%dt:~0,4%"
set "MM=%dt:~4,2%"
set "DD=%dt:~6,2%"
set "backup_date=%YYYY%-%MM%-%DD%"

:: Create dated backup folder
set "backup_folder=%USERPROFILE%\Backups\%backup_date%"
if not exist "%backup_folder%" mkdir "%backup_folder%"

echo.
echo Backing up Documents folder...
xcopy "%USERPROFILE%\Documents\*.docx" "%backup_folder%\" /s /i /y

echo.
echo Checking disk for errors...
echo This may take a while...
echo (This is just a simulation - not actually running chkdsk)
ping -n 3 localhost >nul

echo.
echo Cleaning temporary files...
echo (Simulated - not actually deleting files)
ping -n 2 localhost >nul

echo.
echo Running system file checker...
echo (Simulated - not actually running sfc)
ping -n 3 localhost >nul

echo.
echo ===================================
echo      Maintenance Complete!
echo ===================================
echo.
echo Backup location: %backup_folder%
echo.

:: Ask if user wants to view backup folder
set /p "view_backup=View backup folder? (Y/N): "
if /i "%view_backup%"=="Y" (
    start "" "%backup_folder%"
)

echo.
echo Thank you for using System Maintenance Utility
echo Press any key to exit...
pause >nul 