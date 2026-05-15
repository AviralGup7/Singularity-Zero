@echo off
REM Mutation Testing Runner for Critical Detector Modules
REM Runs mutmut on configured modules and reports mutation score

setlocal enabledelayedexpansion

echo ============================================
echo Mutation Testing - Cyber Security Pipeline
echo ============================================
echo.

REM Check if mutmut is installed
python -m mutmut --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] mutmut is not installed. Run: pip install mutmut
    exit /b 1
)

REM Define target modules
set MODULES=analysis/passive_detector_ssrf.py analysis/passive_detector_idor.py analysis/passive_detector_cors.py analysis/passive_detector_jwt.py analysis/cvss_scoring.py

echo [INFO] Starting mutation testing on critical detector modules...
echo.

set TOTAL_MUTANTS=0
set KILLED_MUTANTS=0
set SURVIVED_MUTANTS=0
set TIMEOUTS=0
set SUSPICIOUS=0

REM Run mutmut on each module
for %%M in (%MODULES%) do (
    echo ----------------------------------------
    echo [RUNNING] Mutating: %%M
    echo ----------------------------------------
    
    REM Run mutmut run for this module
    python -m mutmut run --paths-to-mutate %%M
    
    REM Show results for this module
    echo.
    echo [RESULTS] %%M:
    python -m mutmut results
    
    echo.
)

echo ============================================
echo Overall Mutation Testing Summary
echo ============================================
echo.

REM Show full results
python -m mutmut results

echo.
echo [INFO] To review surviving mutations, run:
echo   python -m mutmut results surviving
echo.
echo [INFO] To apply a specific mutation for inspection:
echo   python -m mutmut apply ^<id^>
echo.
echo [INFO] To revert all mutations:
echo   python -m mutmut revert all
echo.

REM Generate a summary report
echo Mutation testing completed at %date% %time%
echo Report saved to output/mutation_report.txt 2>nul

python -m mutmut results > output/mutation_report.txt 2>&1

echo.
echo [DONE] Mutation testing complete. Check output/mutation_report.txt for details.
