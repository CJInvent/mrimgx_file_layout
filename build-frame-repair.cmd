@echo off
if not "%~1"=="" call "%~1"
if not exist "%~dp0build" mkdir "%~dp0build"
cd /d "%~dp0build"
set "repair_output=repair_frame_bits.exe"
if not "%~2"=="" set "repair_output=%~2"
cl /nologo /std:c++17 /EHsc /O2 /MT /DUNICODE /D_UNICODE /I..\src\dependencies\include ..\tools\repair_frame_bits.cpp /Fe:"%repair_output%" /link /LIBPATH:..\src\dependencies\lib\openssl\release /LIBPATH:..\src\dependencies\lib\zstd\release libcrypto.lib libzstd.lib advapi32.lib user32.lib
exit /b %errorlevel%
