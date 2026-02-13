# Microservice Authentication System

## Auth Service (http://localhost:8081)

### Endpoints

#### 1. Register
```bash
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "username": "username",
  "password": "password123"
}
```

#### 2. Login
```bash
POST /api/auth/login
Content-Type: application/json

{
  "emailOrUsername": "user@example.com",
  "password": "password123"
}
```

#### 3. Refresh Token
```bash
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "your-refresh-token"
}
```

#### 4. Logout
```bash
POST /api/auth/logout
Authorization: Bearer your-access-token
```

#### 5. OAuth2 Google Login
```
GET /api/auth/oauth2/callback/google
```

## API Gateway (http://localhost:8080)

Tất cả requests đi qua gateway trên port 8080:
- `/api/auth/**` - Public (không cần token)
- `/api/**` - Protected (cần Bearer token)

## Setup Instructions

### 1. Cài đặt Prerequisites
- Java 17+
- Maven 3.6+
- PostgreSQL
- Redis

### 2. Tạo Database
```sql
CREATE DATABASE auth_db;
```

### 3. Config Environment Variables (Optional)
```bash
export JWT_SECRET=your-super-secret-key-min-256-bits
export GOOGLE_CLIENT_ID=your-google-client-id
export GOOGLE_CLIENT_SECRET=your-google-client-secret
```

### 4. Start Services
```bash
# Terminal 1 - Auth Service
cd c:\Users\truon\Desktop\java\auth-service
mvn clean install
mvn spring-boot:run

# Terminal 2 - API Gateway  
cd c:\Users\truon\Desktop\java\api-gateway
mvn clean install
mvn spring-boot:run
```

## Testing

### Test với cURL
```bash
# Register
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","username":"testuser","password":"test123"}'

# Login
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"emailOrUsername":"test@test.com","password":"test123"}'

# Access protected endpoint
curl -X GET http://localhost:8080/api/user/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Architecture

```
Mobile/Web Client
       ↓
API Gateway (8080) - JWT Validation
       ↓
Auth Service (8081) - JWT Generation, OAuth2
       ↓
PostgreSQL + Redis
```
