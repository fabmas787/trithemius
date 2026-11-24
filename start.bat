@echo off
REM ==============================================================================
REM Trithemius — 1-Click Launcher for Windows
REM ==============================================================================

if not exist "venv\Scripts\activate.bat" (
    echo [!] Virtual environment not detected. Running installation first...
    call install.bat
)

call venv\Scripts\activate.bat
echo Starting Trithemius Terminal Workstation...
python trithemius.py %*

