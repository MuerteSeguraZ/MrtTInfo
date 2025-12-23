@echo off

git add --all

set "MSG=%~1"
if "%MSG%"=="" set "MSG=Add PEB Module Loader"

git status

git commit -m "%MSG%"

git push origin main

pause
