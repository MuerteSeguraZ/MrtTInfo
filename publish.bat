@echo off

git add --all

set "MSG=%~1"
if "%MSG%"=="" set "MSG=Makefile and overall more tidy (.gitignore)"

git status

git commit -m "%MSG%"

git push origin main

pause
