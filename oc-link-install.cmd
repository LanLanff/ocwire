@echo off
chcp 65001 >nul
title oc-link 安装 + 配置
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0oc-link-install.ps1"
pause
