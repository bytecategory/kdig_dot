$ProgressPreference='SilentlyContinue'
$url='https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/mbedtls-3.6.2.zip'
$out='mbedtls-3.6.2.zip'
& curl.exe -L --fail --proxy http://8.8.8.8:10808 -o $out $url
Expand-Archive -Path mbedtls-3.6.2.zip -DestinationPath C:\Users\usr\Downloads -Force
$env:PATH='winlibs-gcc\mingw64\bin;' + $env:PATH
$srcRoot='mbedtls-mbedtls-3.6.2'
$objDir='build\mbedtls-3.6.2-obj'
Remove-Item $objDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $objDir | Out-Null
Get-ChildItem "$srcRoot\library\*.c" | ForEach-Object {
  & gcc.exe -O2 -I"$srcRoot\include" -c $_.FullName -o (Join-Path $objDir ($_.BaseName + '.o'))
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
& ar rcs build\libmbedtls_bundle.a "$objDir\*.o"
& g++.exe -std=c++20 -O2 -I"$srcRoot\include" -static-libstdc++ -static-libgcc -o kdig_dot.exe kdig_dot.cpp build\libmbedtls_bundle.a -lws2_32 -lbcrypt
