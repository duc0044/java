#!/bin/bash

echo "Starting PostgreSQL and Redis..."
docker-compose up -d

echo "Waiting for services to be ready..."
sleep 5

echo "Building Auth Service..."
cd auth-service
mvn clean install -DskipTests
cd ..

echo "Building API Gateway..."
cd api-gateway
mvn clean install -DskipTests
cd ..

echo "Starting Auth Service..."
cd auth-service
mvn spring-boot:run &
AUTH_PID=$!
cd ..

echo "Waiting for Auth Service to start..."
sleep 10

echo "Starting API Gateway..."
cd api-gateway
mvn spring-boot:run &
GATEWAY_PID=$!
cd ..

echo ""
echo "========================================="
echo "Services are starting..."
echo "========================================="
echo "Auth Service:  http://localhost:8081"
echo "API Gateway:   http://localhost:8080"
echo "PostgreSQL:    localhost:5432"
echo "Redis:         localhost:6379"
echo ""
echo "Press Ctrl+C to stop all services"
echo "========================================="

# Wait for processes
wait $AUTH_PID $GATEWAY_PID
