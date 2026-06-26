@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
    echo vcvars64 failed
    exit /b 1
)
cd /d "%~dp0"
msbuild Updater.sln /t:Build /p:Configuration=Release /p:Platform=x64 /m /v:m /nologo
endlocal
