@echo off
setlocal
echo ========================================================
echo   ZeroExtract Windows Explorer Right-Click Menu Setup
echo ========================================================
echo.

set SCRIPT_DIR=%~dp0
set INSTALL_DIR=%LOCALAPPDATA%\Programs\ZeroExtract

if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

REM Install to standard user application folder to prevent Deny-ACL permission issues
if exist "%SCRIPT_DIR%dist\zeroextract.exe" (
    echo Installing ZeroExtract to: %INSTALL_DIR%
    copy /y "%SCRIPT_DIR%dist\zeroextract.exe" "%INSTALL_DIR%\zeroextract.exe" >nul
    copy /y "%SCRIPT_DIR%zeroextract.ico" "%INSTALL_DIR%\zeroextract.ico" >nul 2>&1
    set LAUNCHER=%INSTALL_DIR%\zeroextract.exe
    set ICON_ARG=%INSTALL_DIR%\zeroextract.ico
) else (
    set LAUNCHER=%SCRIPT_DIR%zeroextract.bat
    set ICON_ARG=%SCRIPT_DIR%zeroextract.ico
)

echo Registering right-click context menu for current user...
echo Target Launcher: %LAUNCHER%
echo.

REM Register context menu for all archive file types (.zip, .rar, .7z, and *)
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
