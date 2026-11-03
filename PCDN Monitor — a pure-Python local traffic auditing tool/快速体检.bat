@echo off
title PCDN 快速体检
cd /d "%~dp0"

set PY=python
where %PY% >nul 2>nul
if errorlevel 1 set PY=py -3

echo 正在采集一轮数据(约3秒)...
%PY% main.py --once

echo.
echo 体检完成。报告: output/report.json
echo 用记事本或浏览器打开即可查看。
echo 如上方显示报错, 请先双击[安装依赖.bat]
pause
