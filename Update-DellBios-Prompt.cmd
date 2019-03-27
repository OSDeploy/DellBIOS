@echo off
::
::	Version 18.05.30
::
::	-Silent
::	powershell -ExecutionPolicy Bypass -Command . "%~dp0Update-DellBios.ps1" -Silent
::	Silently update the BIOS and exit
::
::	-Restart
::	powershell -ExecutionPolicy Bypass -Command . "%~dp0Update-DellBios.ps1" -Restart
::	Silently update the BIOS and restart the computer
::

If "%PROCESSOR_ARCHITEW6432%"=="" GOTO Native
%WinDir%\Sysnative\windowsPowershell\V1.0\PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Update-DellBios.ps1"

GOTO END

:Native
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Update-DellBios.ps1"

:END
exit /b %errorlevel%