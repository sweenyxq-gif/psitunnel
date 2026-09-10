@echo off
title PsiTunnel 1-Click Starter
echo ============================================================
echo Starting PsiTunnel Client & Launching Chrome...
echo ============================================================

:: Start client in a minimized background window if not already running
start /min cmd /c "python cli.py client --server psitunnel.onrender.com --ws-port 443 --transports ws --psk my-super-secret-key-123"

:: Wait 2 seconds for tunnel to establish
timeout /t 2 /nobreak >nul

:: Launch Chrome through SOCKS5 proxy
start "" "C:\Program Files\Google\Chrome\Application\chrome.exe" --proxy-server="socks5://127.0.0.1:1080" --user-data-dir="%TEMP%\chrome_proxy"

echo ============================================================
echo Done! Chrome is open and protected by PsiTunnel.
echo Keep this terminal open while browsing or minimize it.
echo ============================================================
