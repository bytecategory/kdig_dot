@echo off
setlocal

set "ROOT=C:\Users\usr\Downloads"
set "GCC_BIN=%ROOT%\winlibs-gcc\mingw64\bin"
set "MBEDTLS_SRC=%ROOT%\mbedtls-mbedtls-3.6.2"
set "OBJ_DIR=%ROOT%\build\mbedtls-3.6.2-obj"
set "LIB_OUT=%ROOT%\build\libmbedtls_bundle.a"
set "EXE_OUT=%ROOT%\kdig_dot.exe"
set "SRC_CPP=%ROOT%\kdig_dot.cpp"

if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"

for %%F in ("%OBJ_DIR%\*.o") do del /q "%%~fF"

for %%F in ("%MBEDTLS_SRC%\library\*.c") do (
  "%GCC_BIN%\gcc.exe" -O2 -I"%MBEDTLS_SRC%\include" -c "%%~fF" -o "%OBJ_DIR%\%%~nF.o"
  if errorlevel 1 exit /b 1
)

"%GCC_BIN%\ar.exe" rcs "%LIB_OUT%" "%OBJ_DIR%\*.o"
if errorlevel 1 exit /b 1

"%GCC_BIN%\g++.exe" -std=c++20 -O2 -I"%MBEDTLS_SRC%\include" -static-libstdc++ -static-libgcc -o "%EXE_OUT%" "%SRC_CPP%" "%LIB_OUT%" -lws2_32 -lbcrypt
if errorlevel 1 exit /b 1

echo Built %EXE_OUT%
endlocal
