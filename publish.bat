@echo off

git add --all

set "MSG=%~1"
if "%MSG%"=="" set "MSG=Finally fix the shit"

git status

git commit -m "%MSG%"

git push origin main

pause