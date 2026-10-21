@echo off
rem Run from a VS 2022 x64 Native Tools prompt, or pass a compiler setup .bat.
if not "%~1"=="" call "%~1"
if not exist "%~dp0build" mkdir "%~dp0build"
cd /d "%~dp0build"
cl /nologo /std:c++17 /EHsc /O2 /MT /DUNICODE /D_UNICODE /I..\src\dependencies\include ..\src\img_to_vhdx\*.cpp ..\src\libs\encryption\encryption.cpp ..\src\libs\file_operations\file_operations.cpp ..\src\libs\file_reader\file_reader.cpp ..\src\libs\file_reader\metadata_block_reader.cpp ..\src\libs\file_reader\backup_set.cpp ..\src\libs\file_reader\enums_to_text.cpp ..\src\libs\restore\restore.cpp ..\src\libs\restore\crc32.cpp ..\src\libs\vhdx_manager\vhdx_manager.cpp /Fe:img_to_vhdx.exe /link /LIBPATH:..\src\dependencies\lib\openssl\release /LIBPATH:..\src\dependencies\lib\zstd\release /LIBPATH:..\src\dependencies\lib\zlib\release ole32.lib advapi32.lib user32.lib
exit /b %errorlevel%
