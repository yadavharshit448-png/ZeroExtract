@echo off
setlocal
echo Removing ZeroExtract right-click context menu...

reg delete "HKCU\Software\Classes\SystemFileAssociations\.zip\Shell\ZeroExtract" /f >nul 2>&1
reg delete "HKCU\Software\Classes\SystemFileAssociations\.rar\Shell\ZeroExtract" /f >nul 2>&1
reg delete "HKCU\Software\Classes\SystemFileAssociations\.7z\Shell\ZeroExtract" /f >nul 2>&1
reg delete "HKCU\Software\Classes\*\shell\ZeroExtract" /f >nul 2>&1

echo [OK] Removed ZeroExtract from Windows Explorer context menu.
pause
