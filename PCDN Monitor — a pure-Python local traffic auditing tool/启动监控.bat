@echo off
title PCDN 疑似风险监控
cd /d "%~dp0"

set PY=python
where %PY% >nul 2>nul
if errorlevel 1 set PY=py -3

echo ============================================
echo   PCDN 疑似风险监控
echo   提示: 右键本文件选[以管理员身份运行]效果更佳
echo   按 Ctrl+C 停止并自动生成报告
echo ============================================
echo.

%PY% main.py

echo.
echo ============================================
echo  监控已结束。报告在 output/report.json
echo  如上方显示报错, 请先双击[安装依赖.bat]
echo ============================================
pause
