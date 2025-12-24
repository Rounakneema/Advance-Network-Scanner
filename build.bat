@echo off
setlocal enabledelayedexpansion

:: ==========================================================
:: Revealr Build Script (Windows .BAT)
:: ==========================================================
:: Run this from project root:
:: C:\Users\Admin\OneDrive - Shri Vile Parle Kelavani Mandal\Desktop\GO\Advance-Network-Scanner\revealr
:: ==========================================================

echo.
echo ==========================================================
echo --- Starting Revealr Build Process (.BAT) ---
echo ==========================================================
echo.

:: --- 1. Activate Python Virtual Environment ---
if exist ".\venv\Scripts\activate.bat" (
    echo Activating Python virtual environment...
    call .\venv\Scripts\activate.bat
    if %ERRORLEVEL% NEQ 0 (
        echo ERROR: Failed to activate Python venv.
        echo Create it with: python -m venv venv && .\venv\Scripts\activate && pip install grpcio grpcio-tools
        goto :eof
    )
    echo Python venv activated.
) else (
    echo ERROR: venv not found. Create it first with:
    echo python -m venv venv
    goto :eof
)
echo.

:: --- 2. Verify Tools ---
echo Verifying Go, Git, and Protoc...

go version >nul 2>&1 || (echo ERROR: Go not found in PATH. & goto :eof)
git --version >nul 2>&1 || (echo ERROR: Git not found in PATH. & goto :eof)

:: --- 3. Generate Protobuf Code (Conditional) ---
protoc --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo WARNING: Protoc not found in PATH.
    if exist "internal\proto\revealr.pb.go" (
        echo Found existing generated Go files. Skipping generation...
        goto :skip_proto
    ) else (
        echo ERROR: Protoc is required for first-time build.
        goto :eof
    )
)

echo Cleaning old generated protobuf files...
del /Q plugins\ipc\revealr_pb2.py 2>nul
del /Q plugins\ipc\revealr_pb2_grpc.py 2>nul
del /Q internal\proto\revealr.pb.go 2>nul
del /Q internal\proto\revealr_grpc.pb.go 2>nul

echo Generating Go protobuf files...
protoc --proto_path=internal/proto ^
  --go_out=internal/proto --go_opt=paths=source_relative ^
  --go-grpc_out=internal/proto --go-grpc_opt=paths=source_relative ^
  revealr.proto
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Go Protobuf generation failed.
    goto :eof
)

echo Generating Python protobuf files...
python -m grpc_tools.protoc -Iinternal/proto ^
       --python_out=plugins/ipc ^
       --grpc_python_out=plugins/ipc ^
       internal/proto/revealr.proto
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Python Protobuf generation failed.
    goto :eof
)
echo Protobuf code generation completed.

:skip_proto
echo.

:: --- 4. Go Module Tidy ---
echo Running go mod tidy...
go mod tidy
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: go mod tidy failed.
    goto :eof
)
echo Go modules tidied.
echo.

:: --- 5. Build Revealr Executable ---
echo Building Revealr executable...
set CGO_ENABLED=0
go build -o .\cmd\revealr\revealr.exe .\cmd\revealr
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Go build failed.
    goto :eof
)
echo SUCCESS: Revealr built at cmd\revealr\revealr.exe
echo.


:: --- 6. Packaging (Create 'dist' folder) ---
echo.
echo Packaging Release...
set DIST_DIR=dist
if exist "%DIST_DIR%" rmdir /s /q "%DIST_DIR%"
mkdir "%DIST_DIR%"
mkdir "%DIST_DIR%\data"
mkdir "%DIST_DIR%\plugins"
mkdir "%DIST_DIR%\plugins\local"

echo Copying binary...
copy "cmd\revealr\revealr.exe" "%DIST_DIR%\" >nul

echo Copying config and data...
xcopy "data\configs" "%DIST_DIR%\data\configs" /I /E /Y >nul
:: Don't copy DBs or Logs to a fresh install package

echo Copying plugins (excluding __pycache__)...
xcopy "plugins" "%DIST_DIR%\plugins" /I /E /Y /EXCLUDE:tools\xcopy_exclude.txt >nul

echo Copying documentation...
copy "README.md" "%DIST_DIR%\" >nul
copy "LICENSE" "%DIST_DIR%\" >nul

echo Creating setup helper...
(
echo @echo off
echo echo Setting up Revealr Environment...
echo python -m venv venv
echo call venv\Scripts\activate
echo pip install grpcio grpcio-tools
echo echo Setup Complete. Run revealr.exe scan ...
echo pause
) > "%DIST_DIR%\install_dependencies.bat"

echo.
echo ==========================================================
echo Build and Packaging Finished Successfully.
echo Distribution package available in: %DIST_DIR%
echo ==========================================================

pause
