@echo off

git add --all

set "MSG=%~1"
if "%MSG%"=="" set "MSG=made some helper funcs static, also added CPU stuff (affinity, ideal CPU, current CPU)"

git status

git commit -m "%MSG%"

git push origin main

pause
