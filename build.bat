@echo off
setlocal EnableExtensions
pushd "%~dp0"

set "BUILD_DIR=build"
if not defined VCPKG_ROOT if exist "C:\Users\%USERNAME%\vcpkg\scripts\buildsystems\vcpkg.cmake" set "VCPKG_ROOT=C:\Users\%USERNAME%\vcpkg"

where cmake >nul 2>nul
if errorlevel 1 (
    echo [ERROR] CMake was not found on PATH.
    echo [FIX] Install CMake 3.20 or newer.
    popd
    exit /b 1
)

set "TOOLCHAIN="
if defined VCPKG_ROOT if exist "%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" set "TOOLCHAIN=-DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake"
if defined VCPKG_ROOT if not defined OPENSSL_ROOT_DIR set "OPENSSL_ROOT_DIR=%VCPKG_ROOT%\installed\x64-windows"

if defined OPENSSL_ROOT_DIR (
    set "OPENSSL_OPTION=-DOPENSSL_ROOT_DIR=%OPENSSL_ROOT_DIR%"
) else (
    set "OPENSSL_OPTION="
)

cmake -S . -B "%BUILD_DIR%" -DBUILD_TESTING=ON %TOOLCHAIN% %OPENSSL_OPTION%
if errorlevel 1 goto :error
cmake --build "%BUILD_DIR%" --config Release --target rc_agent rc_viewer rc_service remote_crypto_tests -j 4
if errorlevel 1 goto :error
ctest --test-dir "%BUILD_DIR%" -C Release --output-on-failure
if errorlevel 1 goto :error

echo.
echo [OK] Refactored build and tests completed successfully.
echo [INFO] Applications: %BUILD_DIR%\Release\
popd
exit /b 0

:error
echo.
echo [ERROR] Refactored build failed. Check the CMake output above.
popd
exit /b 1
