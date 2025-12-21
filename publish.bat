@echo off

git add --all

set "MSG=%~1"
if "%MSG%"=="" set "MSG=more robust stuff, extra TEB info and more STATUS_*"

git status

git commit -m "%MSG%"

git push origin main

pause
