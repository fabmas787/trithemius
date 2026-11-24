@echo off
REM ==============================================================================
REM Trithemius — Automated Setup for Windows
REM ==============================================================================

setlocal enabledelayedexpansion

echo ======================================================================
echo           TRITHEMIUS — Automated Setup for Windows
echo ======================================================================
echo.

REM 1. Check Python
echo [1/5] Checking Python installation...
set "PY_CMD="

where python >nul 2>nul
if %ERRORLEVEL% equ 0 (
    set "PY_CMD=python"
) else (
    where py >nul 2>nul
    if %ERRORLEVEL% equ 0 (
        set "PY_CMD=py -3"
    )
)

if "%PY_CMD%"=="" (
    echo [!] ERROR: Python 3 was not found on your system!
    echo     Please install Python 3.10+ from https://www.python.org/downloads/
    echo     IMPORTANT: Check the box "Add python.exe to PATH" during installation!
    pause
    exit /b 1
)

echo   Found Python command: %PY_CMD%
%PY_CMD% --version

REM 2. Check Ollama
echo.
echo [2/5] Checking Ollama for Windows...
where ollama >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo   Found Ollama:
    ollama --version
) else (
    echo   [!] NOTICE: Ollama was not detected in PATH.
    echo       Download and install it from: https://ollama.com/download/windows
    echo       (Continuing setup; you can install Ollama later)
)

REM 3. Virtual Environment
echo.
echo [3/5] Setting up Python virtual environment (venv)...
if not exist "venv" (
    echo   Creating virtual environment in venv\...
    %PY_CMD% -m venv venv
    if %ERRORLEVEL% neq 0 (
        echo   [!] Failed to create venv. Ensure virtualenv module is available.
        pause
        exit /b 1
    )
    echo   Virtual environment created successfully.
) else (
    echo   Existing virtual environment found.
)

REM 4. Activate & Install Dependencies
echo.
echo [4/5] Installing Python dependencies...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip --quiet
python -m pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
    echo   [!] Dependency installation encountered errors.
    pause
    exit /b 1
)
echo   All Python dependencies installed successfully.

REM 5. Ollama Models Check
echo.
echo [5/5] Checking Ollama models...
where ollama >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo   Pulling required embedding model (nomic-embed-text)...
    ollama pull nomic-embed-text
    echo   Pulling primary LLM (SparkLLM/Spark-X2.5-4B)...
    ollama pull SparkLLM/Spark-X2.5-4B
)

echo.
echo ======================================================================
echo                    SETUP COMPLETED SUCCESSFULLY!
echo ======================================================================
echo.
echo To start the Trithemius Terminal Workstation, double click:
echo   start.bat
echo.
echo Or run in terminal:
echo   venv\Scripts\activate
echo   python trithemius.py
echo.
pause
