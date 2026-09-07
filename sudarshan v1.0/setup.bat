@echo off
setlocal enabledelayedexpansion
title Sudarshan - Setup

echo ============================================
echo   Sudarshan - Setup
echo ============================================
echo.

:: 1. Ollama
where ollama >nul 2>nul
if %errorlevel% neq 0 (
    echo [1/6] Ollama not found. Downloading installer...
    powershell -Command "Invoke-WebRequest -Uri https://ollama.com/download/OllamaSetup.exe -OutFile OllamaSetup.exe"
    start /wait OllamaSetup.exe
    del OllamaSetup.exe
) else (
    echo [1/6] Ollama already installed. Skipping.
)
echo.

:: 2. Models
echo [2/6] Pulling models (qwen2.5:7b-instruct, ~5GB)...
ollama pull qwen2.5:7b-instruct
ollama pull nomic-embed-text
echo.

:: 3. searchsploit note (not natively available on Windows)
echo [3/6] Note: searchsploit is a Linux tool (part of ExploitDB).
echo       On Windows, run this project under WSL2 (Kali or Ubuntu) for
echo       full exploit-lookup support, or skip exploit lookups with
echo       --exploitdb-only disabled in session_builder.py calls.
echo.

:: 4. Python environment
echo [4/6] Setting up Python environment...
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: Python not found. Install Python 3.10+ from python.org and re-run.
    pause
    exit /b 1
)

if not exist venv (
    python -m venv venv
)
call venv\Scripts\activate.bat

echo Installing Python dependencies...
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
echo.

:: 5. .env check
echo [5/6] Checking for .env (NVD_API_KEY)...
if not exist .env (
    echo   [!] No .env found. Copy .env.example to .env and add your NVD API key.
) else (
    echo   .env found.
)
echo.

:: 6. Seed RAG store
echo [6/6] Seeding RAG vector store...
python report_generator.py --seed-rag

echo.
echo ============================================
echo   Setup complete.
echo ============================================
echo.
echo Next steps:
echo   1. Copy .env.example to .env and add your NVD API key (if not done)
echo   2. venv\Scripts\activate.bat
echo   3. python sudarshan.py
echo.
pause
