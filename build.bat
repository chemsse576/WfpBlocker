@echo off
setlocal

if not exist build mkdir build
cd build

cmake -G "Visual Studio 18 2026" -A x64 .. || (
    echo [!] CMake configuration failed
    exit /b 1
)

cmake --build . --config Release || (
    echo [!] Build failed
    exit /b 1
)

echo.
echo [+] Build OK: build\Release\WfpBlocker.exe
