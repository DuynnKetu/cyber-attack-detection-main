@echo off
echo ========================================
echo   HYBRID WAF SYSTEM - QUICK START
echo ========================================
echo.
echo Huong dan chay he thong:
echo.
echo 1. Terminal 1: Chay Backend Web App
echo    ^> python web_app.py
echo.
echo 2. Terminal 2: Chay WAF Proxy
echo    ^> python waf_proxy.py
echo.
echo 3. Terminal 3: Test Attack Simulator
echo    ^> python attack_sim.py
echo.
echo ========================================
echo.
pause

echo.
echo Dang khoi dong Backend Web App...
echo.
start cmd /k "python web_app.py"

timeout /t 3 /nobreak >nul

echo Dang khoi dong WAF Proxy...
echo.
start cmd /k "python waf_proxy.py"

timeout /t 3 /nobreak >nul

echo.
echo ========================================
echo   HE THONG DA KHOI DONG!
echo ========================================
echo.
echo Backend Web App: http://localhost:5001
echo WAF Proxy:       http://localhost:5000
echo WAF Stats:       http://localhost:5000/waf/stats
echo.
echo Truy cap web app qua WAF: http://localhost:5000
echo.
echo Nhan Enter de chay Attack Simulator...
pause

python attack_sim.py

echo.
echo Hoan thanh!
pause
