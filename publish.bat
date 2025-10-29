@echo off

git add --all

set "MSG=%~1"
if "%MSG%"=="" set "MSG=WaitReason and ThreadState readable strings"

git status

git commit -m "%MSG%"

git push origin main

pause
