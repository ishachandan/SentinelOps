@echo off
REM Quick start script for Docker on Windows

echo ======================================
echo SentinelOps Docker Quick Start
echo ======================================
echo.

REM Check if .env exists
if not exist .env (
    echo [ERROR] .env file not found!
    echo.
    echo Please create .env file from .env.example:
    echo   copy .env.example .env
    echo.
    echo Then edit .env with your API keys.
    pause
    exit /b 1
)

echo [1/3] Validating setup...
python validate_docker.py
if errorlevel 1 (
    echo.
    echo [ERROR] Validation failed. Please fix the issues above.
    pause
    exit /b 1
)

echo.
echo [2/3] Building Docker image...
docker-compose build
if errorlevel 1 (
    echo.
    echo [ERROR] Docker build failed!
    pause
    exit /b 1
)

echo.
echo [3/3] Starting services...
docker-compose up -d
if errorlevel 1 (
    echo.
    echo [ERROR] Failed to start services!
    pause
    exit /b 1
)

echo.
echo ======================================
echo Success! SentinelOps is running.
echo ======================================
echo.
echo Open your browser to: http://localhost:5000
echo.
echo Useful commands:
echo   docker-compose logs -f     (View logs)
echo   docker-compose down        (Stop services)
echo   docker-compose ps          (Check status)
echo.
pause
