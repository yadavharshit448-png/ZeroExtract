@echo off
setlocal
REM ZeroExtract Windows Batch Launcher
REM Enables drag-and-drop or CLI execution on Windows

set PY_CMD=python
where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    if exist "C:\Program Files\Python312\python.exe" (
        set PY_CMD="C:\Program Files\Python312\python.exe"
    )
)

%PY_CMD% "D:\New folder\run_zeroextract.py" %*
