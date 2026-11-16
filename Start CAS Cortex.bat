@echo off
rem Opens the CAS Cortex desktop app without a console window.
if not exist "%~dp0.venv\Scripts\pythonw.exe" (
  echo CAS Cortex is not set up yet. Running setup first...
  call "%~dp0setup.bat"
)
start "" "%~dp0.venv\Scripts\pythonw.exe" "%~dp0launch_gui.pyw"
