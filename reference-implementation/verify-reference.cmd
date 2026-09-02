@echo off
setlocal EnableExtensions

rem Run this script from any working directory.
set "SCRIPT_DIR=%~dp0"
set "VECTOR_FILE=%SCRIPT_DIR%..\tests\Xilent.KeyDeriver.Tests\TestVectors\derivation-vectors.json"
set "VECTOR_MARKDOWN=%SCRIPT_DIR%reference-test-vectors.md"
set "DERIVER=%SCRIPT_DIR%derive_key.py"

rem Add future reference implementations as additional commands below.

if not exist "%VECTOR_FILE%" (
    echo FAIL: Test vector file was not found: "%VECTOR_FILE%"
    exit /b 1
)
if not exist "%DERIVER%" (
    echo FAIL: Reference implementation was not found: "%DERIVER%"
    exit /b 1
)

where py >nul 2>&1
if not errorlevel 1 (
    set "PYTHON=py"
) else (
    where python >nul 2>&1
    if errorlevel 1 (
        echo FAIL: Python 3 was not found. Install Python 3 or add it to PATH.
        exit /b 1
    )
    set "PYTHON=python"
)

rem Export the same vectors used by the C# tests before executing verification.
%PYTHON% "%DERIVER%" --write-test-vector-markdown "%VECTOR_FILE%" "%VECTOR_MARKDOWN%"
if errorlevel 1 (
    echo FAIL: Could not create "%VECTOR_MARKDOWN%"
    exit /b 1
)

rem Execute the current reference implementation.
%PYTHON% "%DERIVER%" --verify-test-vectors "%VECTOR_FILE%"
if errorlevel 1 (
    echo Reference verification result: FAIL
    exit /b 1
)

echo Reference verification result: PASS
exit /b 0
