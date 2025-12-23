@echo off

git add --all

set "MSG=%~1"
if "%MSG%"=="" set "MSG=rename helpers to MrtHelper_*, added ExceptionList to TEB and SEH Walk helper."

git status

git commit -m "%MSG%"

git push origin main

pause
