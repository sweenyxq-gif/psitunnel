@echo off
title PsiTunnel 24/7 Keep-Alive Pinger
echo Starting PsiTunnel Render Keepalive Service...
python scripts\keepalive.py --url https://psitunnel.onrender.com --interval 600
pause
