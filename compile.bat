@echo off
REM ================================
REM Compile MrtTInfo + main.c using MinGW
REM ================================

REM Source files
set SOURCES=MrtTInfo.c main.c

REM Output executable
set OUTPUT=MrtTInfoTest.exe

REM Compile command
gcc -std=c11 -Wall -O2 -municode %SOURCES% -o %OUTPUT% -lntdll

IF %ERRORLEVEL% EQU 0 (
    echo Build succeeded: %OUTPUT%
) ELSE (
    echo Build failed
)
pause
