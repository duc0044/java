@echo off
echo ===============================================
echo      LOCAL DEVELOPMENT SETUP
echo ===============================================
echo.

REM Check if Docker is running
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Docker is not installed or not running
    echo Please install Docker Desktop and start it
    pause
    exit /b 1
)

echo Step 1: Starting PostgreSQL and Redis with Docker...
docker run --name postgres-local -e POSTGRES_DB=auth_db -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres:15-alpine 2>nul || echo PostgreSQL container already exists
docker run --name redis-local -p 6379:6379 -d redis:7-alpine 2>nul || echo Redis container already exists

echo Waiting for databases to be ready...
timeout /t 5 /nobreak > nul

echo.
echo Step 2: Building Auth Service...
cd auth-service
call mvn clean install -DskipTests
if %errorlevel% neq 0 (
    echo ERROR: Auth Service build failed
    pause
    exit /b 1
)
cd ..

echo.
echo Step 3: Building API Gateway...
cd api-gateway
call mvn clean install -DskipTests
if %errorlevel% neq 0 (
    echo ERROR: API Gateway build failed
    pause
    exit /b 1
)
cd ..

echo.
echo ===============================================
echo Starting Services with Local Configuration...
echo ===============================================

echo Starting Auth Service on port 8081...
start "Auth Service" cmd /k "cd auth-service && mvn spring-boot:run -Dspring-boot.run.profiles=local"

echo Waiting for Auth Service to start...
timeout /t 15 /nobreak > nul

echo Starting API Gateway on port 8080...
start "API Gateway" cmd /k "cd api-gateway && mvn spring-boot:run -Dspring-boot.run.profiles=local"

echo.
echo ===============================================
echo           SERVICES STARTED!
echo ===============================================
echo Auth Service:     http://localhost:8081
echo API Gateway:      http://localhost:8080
echo PostgreSQL:       localhost:5432
echo Redis:            localhost:6379
echo.
echo Database credentials:
echo   Database: auth_db
echo   Username: postgres  
echo   Password: postgres
echo.
echo Check the opened terminal windows for logs
echo Close the terminal windows to stop services
echo ===============================================
pause