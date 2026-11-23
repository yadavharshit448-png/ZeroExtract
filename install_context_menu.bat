@echo off
setlocal
echo ========================================================
echo   ZeroExtract Windows Explorer Right-Click Menu Setup
echo ========================================================
echo.

set SCRIPT_DIR=%~dp0
set LAUNCHER=%SCRIPT_DIR%zeroextract.bat

REM Check if standalone exe exists, prefer exe if present
if exist "%SCRIPT_DIR%dist\zeroextract.exe" (
    set LAUNCHER=%SCRIPT_DIR%dist\zeroextract.exe
)

echo Registering right-click context menu for current user...
echo Target Launcher: %LAUNCHER%
echo.

REM Add to all archive file types under Current User registry (no Admin required)
set ICON_ARG=%SCRIPT_DIR%zeroextract.ico
if not exist "%ICON_ARG%" (
    set ICON_ARG=%LAUNCHER%,0
)

reg add "HKCU\Software\Classes\SystemFileAssociations\.zip\Shell\ZeroExtract" /ve /d "Extract with ZeroExtract (No Extra Space)" /f >nul
reg add "HKCU\Software\Classes\SystemFileAssociations\.zip\Shell\ZeroExtract" /v "Icon" /d "\"%ICON_ARG%\"" /f >nul
reg add "HKCU\Software\Classes\SystemFileAssociations\.zip\Shell\ZeroExtract\command" /ve /d "cmd.exe /k \"\"%LAUNCHER%\" \"%%1\"\"" /f >nul

reg add "HKCU\Software\Classes\SystemFileAssociations\.rar\Shell\ZeroExtract" /ve /d "Extract with ZeroExtract (No Extra Space)" /f >nul
reg add "HKCU\Software\Classes\SystemFileAssociations\.rar\Shell\ZeroExtract" /v "Icon" /d "\"%ICON_ARG%\"" /f >nul
reg add "HKCU\Software\Classes\SystemFileAssociations\.rar\Shell\ZeroExtract\command" /ve /d "cmd.exe /k \"\"%LAUNCHER%\" \"%%1\"\"" /f >nul

reg add "HKCU\Software\Classes\SystemFileAssociations\.7z\Shell\ZeroExtract" /ve /d "Extract with ZeroExtract (No Extra Space)" /f >nul
reg add "HKCU\Software\Classes\SystemFileAssociations\.7z\Shell\ZeroExtract" /v "Icon" /d "\"%ICON_ARG%\"" /f >nul
reg add "HKCU\Software\Classes\SystemFileAssociations\.7z\Shell\ZeroExtract\command" /ve /d "cmd.exe /k \"\"%LAUNCHER%\" \"%%1\"\"" /f >nul

reg add "HKCU\Software\Classes\*\shell\ZeroExtract" /ve /d "Extract with ZeroExtract (No Extra Space)" /f >nul
reg add "HKCU\Software\Classes\*\shell\ZeroExtract" /v "Icon" /d "\"%ICON_ARG%\"" /f >nul
reg add "HKCU\Software\Classes\*\shell\ZeroExtract\command" /ve /d "cmd.exe /k \"\"%LAUNCHER%\" \"%%1\"\"" /f >nul

echo [OK] Successfully registered!
echo You can now right-click any .zip, .rar, .7z, or archive file in Windows Explorer
echo and click "Extract with ZeroExtract (No Extra Space)".
echo.
pause
