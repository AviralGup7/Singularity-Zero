@echo off
REM ============================================================
REM Dependency Security Audit Script
REM Runs pip-audit and safety checks against the current environment
REM ============================================================

setlocal enabledelayedexpansion

echo ============================================
echo Dependency Security Audit
echo ============================================
echo.

REM Check if pip-audit is installed
where pip-audit >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] pip-audit not found. Installing...
    pip install pip-audit
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to install pip-audit. Aborting.
        exit /b 1
    )
)

REM Check if safety is installed
where safety >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] safety not found. Installing...
    pip install safety
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to install safety. Aborting.
        exit /b 1
    )
)

echo [1/2] Running pip-audit...
echo --------------------------------------------
pip-audit --format=columns 2>&1
set "PIP_AUDIT_EXIT_CODE=%errorlevel%"
echo --------------------------------------------
echo.

if %PIP_AUDIT_EXIT_CODE% equ 0 (
    echo [OK] pip-audit: No known vulnerabilities found.
) else (
    echo [FAIL] pip-audit: Known vulnerabilities detected!
    echo        Review the output above and update affected packages.
)
echo.

echo [2/2] Running safety check...
echo --------------------------------------------
safety check 2>&1
set "SAFETY_EXIT_CODE=%errorlevel%"
echo --------------------------------------------
echo.

if %SAFETY_EXIT_CODE% equ 0 (
    echo [OK] safety: No known vulnerabilities found.
) else (
    echo [FAIL] safety: Known vulnerabilities detected!
    echo        Review the output above and update affected packages.
)
echo.

echo ============================================
echo Audit Summary
echo ============================================
echo pip-audit exit code: %PIP_AUDIT_EXIT_CODE%
echo safety exit code:    %SAFETY_EXIT_CODE%
echo.

if %PIP_AUDIT_EXIT_CODE% equ 0 if %SAFETY_EXIT_CODE% equ 0 (
    echo [PASS] All dependency checks passed.
    exit /b 0
) else (
    echo [FAIL] One or more dependency checks failed.
    exit /b 1
)
