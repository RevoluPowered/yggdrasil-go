@echo off
setlocal enabledelayedexpansion

set PKGSRC=github.com/yggdrasil-network/yggdrasil-go/src/version

set LDFLAGS=-X %PKGSRC%.buildName=%PKGNAME% -X %PKGSRC%.buildVersion=%PKGVER%
set ARGS=-v
set BUILDMODE=c-shared
set OUTPUT=

:parse_args
if "%1"=="" goto end_args
if "%1"=="-s" set BUILDMODE=c-archive
if "%1"=="-t" set TABLES=true
if "%1"=="-d" set ARGS=%ARGS% -tags debug & set DEBUG=true
if "%1"=="-c" (
  shift
  set GCFLAGS=%GCFLAGS% %1
)
if "%1"=="-l" (
  shift
  set LDFLAGS=%LDFLAGS% %1
)
if "%1"=="-o" (
  shift
  set OUTPUT=%1
)
shift
goto parse_args

:end_args
if "%TABLES%"=="" if "%DEBUG%"=="" (
  set LDFLAGS=%LDFLAGS% -s -w
)

if "%OUTPUT%"=="" (
  if "%BUILDMODE%"=="c-shared" (
    set OUTPUT=yggdrasil.dll
  ) else (
    set OUTPUT=yggdrasil.a
  )
)

echo Building: %OUTPUT% (mode: %BUILDMODE%)
set CGO_ENABLED=1
go build %ARGS% -buildmode=%BUILDMODE% -o %OUTPUT% -ldflags="%LDFLAGS%" -gcflags="%GCFLAGS%" ./contrib/lib

echo Done: %OUTPUT%
