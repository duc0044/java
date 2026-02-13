@echo off
echo Starting PostgreSQL and Redis...
docker-compose up -d

echo Waiting for services to be ready...
timeout /t 5 /nobreak > nul

echo Building Auth Service...
cd auth-service
call mvn clean install -DskipTests
cd ..

echo Building API Gateway...
cd api-gateway
call mvn clean install -DskipTests
cd ..

echo =========================================
echo Starting Auth Service on port 8081...
echo =========================================
start "Auth Service" cmd /k "cd auth-service && mvn spring-boot:run"

echo Waiting for Auth Service to start...
timeout /t 10 /nobreak > nul

echo =========================================
echo Starting API Gateway on port 8080...
echo =========================================
start "API Gateway" cmd /k "cd api-gateway && mvn spring-boot:run"

echo.
echo =========================================
echo Services are starting...
echo =========================================
echo Auth Service:  http://localhost:8081
echo API Gateway:   http://localhost:8080
echo PostgreSQL:    localhost:5432
echo Redis:         localhost:6379
echo.
echo Check the opened terminal windows for logs
echo Close the terminal windows to stop services
echo =========================================
pause
