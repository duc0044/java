# Microservice Authentication System

## Architecture Overview

Hệ thống gồm 4 microservices:
- **API Gateway** (Port 8080) - Route requests và validate JWT
- **Auth Service** (Port 8081) - Authentication, Authorization, User/Role/Permission Management
- **Order Service** (Port 8082) - Order và Report Management
- **File Service** (Port 8083) - File Storage với MinIO

## Services

### Auth Service (http://localhost:8081)

Quản lý authentication và authorization.

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

#### 6. Upload Avatar
```bash
POST /api/users/{id}/avatar
Authorization: Bearer <access_token>
Content-Type: multipart/form-data

Form Data:
- file: [Image File] (max 10MB)
```

#### 7. Delete Avatar
```bash
DELETE /api/users/{id}/avatar
Authorization: Bearer <access_token>
```

**Avatar Features:**
- ✅ Auto default avatar theo role (Admin/User)
- ✅ Custom avatar upload (max 10MB)
- ✅ Avatar organized by user ID: `avatars/user-{id}/`
- ✅ Auto-switch default avatar khi role thay đổi
- 📖 Chi tiết: [AVATAR_GUIDE.md](AVATAR_GUIDE.md)

**Note**: Users can only upload/delete their own avatar unless they have ADMIN role.


### Order Service (http://localhost:8082)

Quản lý đơn hàng và báo cáo. Xem chi tiết tại [order-service/README.md](order-service/README.md)

#### Main Endpoints:
- `GET /api/orders` - Lấy danh sách đơn hàng
- `POST /api/orders` - Tạo đơn hàng mới
- `POST /api/orders/{id}/approve` - Phê duyệt đơn hàng
- `POST /api/orders/{id}/reject` - Từ chối đơn hàng
- `GET /api/reports` - Lấy danh sách báo cáo
- `POST /api/reports/{id}/export` - Export báo cáo

### File Service (http://localhost:8083)

Quản lý file storage với MinIO. Xem chi tiết tại [file-service/README.md](file-service/README.md)

#### Main Endpoints:
- `POST /api/files/upload` - Upload file (max 100MB)
- `GET /api/files/download/{folder}/{filename}` - Download file
- `GET /api/files/url/{folder}/{filename}` - Get presigned URL (temporary access)
- `DELETE /api/files/{folder}/{filename}` - Delete file (Admin only)
- `GET /api/files/metadata/{folder}/{filename}` - Get file metadata
- `GET /api/files/exists/{folder}/{filename}` - Check file existence

#### MinIO Console:
- **URL**: http://localhost:9001
- **Username**: minioadmin
- **Password**: minioadmin123

## API Gateway (http://localhost:8080)

Tất cả requests đi qua gateway trên port 8080:
- `/api/auth/**` → Auth Service (public, không cần token)
- `/api/orders/**` → Order Service (protected)
- `/api/reports/**` → Order Service (protected)
- `/api/files/**` → File Service (protected)
- `/api/**` → Auth Service (protected, user/role/permission management)

## Setup Instructions

### 1. Cài đặt Prerequisites
- Java 17+
- Maven 3.6+
- PostgreSQL
- Redis

### 2. Tạo Database
```sql
CREATE DATABASE auth_db;
CREATE DATABASE order_db;
```

### 3. Config Environment Variables (Optional)
```bash
export JWT_SECRET=your-super-secret-key-min-256-bits
export GOOGLE_CLIENT_ID=your-google-client-id
export GOOGLE_CLIENT_SECRET=your-google-client-secret
```

### 4. Start Services

#### Với Docker Compose (Khuyến nghị)
```bash
cd java
docker-compose up
```

#### Hoặc chạy từng service riêng
```bash
# Terminal 1 - Auth Service
cd java/auth-service
mvn clean install
mvn spring-boot:run

# Terminal 2 - Order Service
cd java/order-service
mvn clean install
mvn spring-boot:run

# Terminal 3 - API Gateway  
cd java/api-gateway
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
API Gateway (8080) - Route & JWT Validation
       ↓
    ┌──┴────────────────────────────┐
    ↓                ↓               ↓
Auth Service    Order Service   File Service
  (8081)          (8082)          (8083)
- Authentication - Orders        - File Upload
- Authorization  - Reports       - File Download
- User/Role/Perm - JWT Validate  - MinIO Storage
    ↓                ↓               ↓
PostgreSQL +     PostgreSQL       MinIO
  Redis          (order_db)      (Object Storage)
(auth_db)
```

## Key Features

- ✅ **Microservices Architecture** - Services độc lập, dễ scale
- ✅ **JWT Authentication** - Stateless authentication
- ✅ **OAuth2 Google Login** - Social login
- ✅ **Role-Based Access Control** - Quản lý quyền chi tiết
- ✅ **API Gateway** - Single entry point, routing
- ✅ **Separate Databases** - Mỗi service có database riêng
- ✅ **Object Storage (MinIO)** - S3-compatible file storage
- ✅ **Docker Support** - Dễ dàng deploy
- ✅ **Redis Cache** - Performance optimization (auth-service)
