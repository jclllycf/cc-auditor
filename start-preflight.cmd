@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist "%SystemRoot%\System32\msvcp140.dll" goto runtime
if not exist "%SystemRoot%\System32\vcruntime140_1.dll" goto runtime
CC_Auditor.exe --scan --interactive
if errorlevel 1 (
  echo 如提示 DLL 或入口点缺失，请先安装微软官方最新 Visual C++ x64 运行库。
  echo 安装说明：INSTALL_WINDOWS_ZH.md
  pause
)
exit /b
:runtime
echo 此电脑缺少 Microsoft Visual C++ x64 运行库。
echo 请从微软官方页面下载并安装，再重新启动本工具：
echo https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist
echo 本工具不会自动下载、安装或更改系统设置。
pause
exit /b 3
