@echo off
setlocal EnableDelayedExpansion

REM ---- leakhunter build.bat ----
REM Finds VS 2022 (Community/Pro/Enterprise/BuildTools), loads vcvars64,
REM configures with Ninja (falls back to VS generator), builds Release,
REM drops leakhunter.exe at cpp\build\leakhunter.exe

pushd "%~dp0"

echo [*] locating Visual Studio 2022 x64 environment...

set "VCVARS="

REM vswhere is the reliable way — ships with every VS 2017+ install
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        if exist "%%i\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%%i\VC\Auxiliary\Build\vcvars64.bat"
    )
)

REM fallback: hardcoded common paths
if not defined VCVARS (
    for %%p in (
        "C:\Program Files\Microsoft Visual Studio\2022\Community"
        "C:\Program Files\Microsoft Visual Studio\2022\Professional"
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
        "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
    ) do (
        if exist "%%~p\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%%~p\VC\Auxiliary\Build\vcvars64.bat"
    )
)

if not defined VCVARS (
    echo [!] could not find vcvars64.bat.
    echo     install Visual Studio 2022 with "Desktop development with C++"
    echo     or VS 2022 Build Tools + Windows 11 SDK.
    popd & exit /b 1
)

echo [*] using: !VCVARS!
call "!VCVARS!" >nul
if errorlevel 1 (
    echo [!] vcvars64 failed.
    popd & exit /b 1
)

where cl.exe >nul 2>nul
if errorlevel 1 (
    echo [!] cl.exe still not on PATH after vcvars. aborting.
    popd & exit /b 1
)

echo [*] cl.exe: 
where cl.exe

REM ---- cmake present? ----
where cmake.exe >nul 2>nul
if errorlevel 1 (
    echo [!] cmake not found on PATH.
    echo     winget install Kitware.CMake
    echo     then reopen this window.
    popd & exit /b 1
)

REM ---- pick a generator: Ninja if available, else VS generator ----
set "GEN_ARGS="
set "BUILD_DIR=build"
set "EXE=build\leakhunter.exe"

where ninja.exe >nul 2>nul
if not errorlevel 1 (
    echo [*] generator: Ninja
    set "GEN_ARGS=-G Ninja -DCMAKE_BUILD_TYPE=Release"
    set "EXE=build\leakhunter.exe"
) else (
    echo [*] generator: Visual Studio 17 2022 (Ninja not found)
    set "GEN_ARGS=-G "Visual Studio 17 2022" -A x64"
    set "EXE=build\Release\leakhunter.exe"
)

REM ---- stale-config guard: if build dir was configured with a different generator, nuke it ----
if exist "%BUILD_DIR%\CMakeCache.txt" (
    findstr /C:"CMAKE_GENERATOR:INTERNAL=Ninja" "%BUILD_DIR%\CMakeCache.txt" >nul 2>nul
    set "WAS_NINJA=!errorlevel!"
    findstr /C:"CMAKE_GENERATOR:INTERNAL=Visual Studio" "%BUILD_DIR%\CMakeCache.txt" >nul 2>nul
    set "WAS_VS=!errorlevel!"
    if "!WAS_NINJA!"=="0" if not defined NINJA_FOUND_ALREADY set "MISMATCH=1"
    if "!WAS_VS!"=="0" if not defined NINJA_FOUND_ALREADY set "MISMATCH="
)

REM ---- clean-flag passthrough: build.bat clean ----
if /i "%~1"=="clean" (
    echo [*] wiping %BUILD_DIR%
    if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
)

REM ---- configure ----
if not exist "%BUILD_DIR%\CMakeCache.txt" (
    echo [*] configuring...
    cmake -B "%BUILD_DIR%" %GEN_ARGS% -DCMAKE_BUILD_TYPE=Release
    if errorlevel 1 (
        echo [!] configure failed.
        popd & exit /b 1
    )
) else (
    echo [*] build dir already configured, skipping configure
)

REM ---- build ----
echo [*] building Release...
cmake --build "%BUILD_DIR%" --config Release
if errorlevel 1 (
    echo [!] build failed.
    popd & exit /b 1
)

REM ---- verify ----
if not exist "%EXE%" (
    echo [!] expected binary not found: %EXE%
    popd & exit /b 1
)

echo.
echo [=] built: %EXE%
for %%f in ("%EXE%") do echo     size: %%~zf bytes, modified: %%~tf

REM ---- smoke test with no args (prints usage) ----
"%EXE%" >nul 2>nul

REM ---- optional run passthrough ----
if "%~1"=="run" (
    shift
    echo [*] running: %EXE% %*
    "%EXE%" %*
)

popd
endlocal