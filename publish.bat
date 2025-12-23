@echo off

git add --all

set "MSG=%~1"
if "%MSG%"=="" set "MSG=SubsystemTib (only gives 32-bit value in x86, x64 effectively unuses SubsystemTib)"

git status

git commit -m "%MSG%"

git push origin main

pause
