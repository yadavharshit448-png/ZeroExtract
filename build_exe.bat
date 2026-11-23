@echo off
setlocal
echo ========================================================
echo        ZeroExtract Standalone Executable Builder
echo ========================================================
echo.

echo [1/3] Checking / Installing PyInstaller...
python -m pip install --upgrade pyinstaller setuptools wheel

echo.
echo [2/3] Building standalone zeroextract.exe...
python -m PyInstaller --onefile --name zeroextract --clean run_zeroextract.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Build failed! Check the output above.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo [3/3] Success! Standalone executable created at:
echo       dist\zeroextract.exe
echo.
echo You can now distribute dist\zeroextract.exe to anyone.
echo They do NOT need Python installed to use it.
echo.
pause
