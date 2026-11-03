@echo off
title 安装依赖
cd /d "%~dp0"

set PY=python
where %PY% >nul 2>nul
if errorlevel 1 set PY=py -3

echo 正在安装依赖(psutil 必需 / rich 可选)...
%PY% -m pip install -r requirements.txt

echo.
echo 安装完成。如无红色报错即可双击[启动监控.bat]
pause
