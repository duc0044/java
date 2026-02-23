# Backend API Documentation - Microservice System

## 📋 Tổng quan

Hệ thống microservices với kiến trúc Spring Boot gồm 4 services chính:
- **API Gateway** (Port 8080) - Định tuyến requests và xác thực JWT
- **Auth Service** (Port 8081) - Quản lý Authentication, Authorization, Users, Roles, Permissions
- **Order Service** (Port 8082) - Quản lý đơn hàng và báo cáo
- **File Service** (Port 8083) - Lưu trữ files với MinIO

---

## 🌐 API Gateway

**Base URL**: `http://localhost:8080`

Tất cả requests từ client đều đi qua Gateway này. Gateway sẽ định tuyến đến các services tương ứng:

| Route Pattern | Service Đích | Security |
|--------------|--------------|----------|
| `/api/auth/**` | Auth Service | Public (không cần token) |
| `/api/oauth2/**` | Auth Service | Public (OAuth2 flow) |
| `/api/users/**` | Auth Service | Protected |
| `/api/roles/**` | Auth Service | Protected |
| `/api/permissions/**` | Auth Service | Protected |
| `/api/orders/**` | Order Service | Protected |
| `/api/reports/**` | Order Service | Protected |
| `/api/files/**` | File Service | Protected |

**Protected Routes**: Yêu cầu header `Authorization: Bearer <access_token>`

---

## 🔐 Auth Service APIs

### 1. Authentication

#### 1.1. Đăng ký (Register)
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "username": "username",
  "password": "password123"
}
```

**Response (200 OK)**:
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIs...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "username": "username",
    "roles": "ROLE_USER",
    "permissions": null,
    "avatarUrl": "avatars/default/user-avatar.png"
  }
}
```

#### 1.2. Đăng nhập (Login)
```http
POST /api/auth/login
Content-Type: application/json

{
  "emailOrUsername": "user@example.com",
  "password": "password123"
}
```

**Response (200 OK)**: Giống response của Register

#### 1.3. Google OAuth2 Login
```
GET /api/auth/oauth2/authorization/google
```
- Redirect user đến trang login Google
- Sau khi xác thực thành công, redirect về: `http://localhost:3000/auth/callback?accessToken=...&refreshToken=...`

#### 1.4. Refresh Token
```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Response (200 OK)**:
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIs...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIs..."
}
```

#### 1.5. Logout
```http
POST /api/auth/logout
Authorization: Bearer <access_token>
```

**Response (200 OK)**: `"Logged out successfully"`

#### 1.6. Get Current User Profile
```http
GET /api/auth/me
Authorization: Bearer <access_token>
```

**Response (200 OK)**:
```json
{
  "id": 1,
  "email": "user@example.com",
  "username": "username",
  "roles": "ROLE_USER",
  "permissions": null,
  "avatarUrl": "avatars/user-1/abc123.jpg"
}
```

#### 1.7. Get Dashboard Summary (Admin Only)
```http
GET /api/auth/dashboard/summary
Authorization: Bearer <access_token>
```

**Required Permission**: `ROLE_ADMIN`, `ROLE_MANAGER`, hoặc `ROLE_STAFF`

**Response (200 OK)**:
```json
{
  "totalUsers": 25,
  "activeSessions": 10,
  "systemHealth": "Excellent",
  "recentActivity": [
    "User john_doe logged in",
    "User admin updated role for user123",
    "New user registered: newuser@example.com"
  ]
}
```

---

### 2. User Management

#### 2.1. Get All Users (Paginated)
```http
GET /api/users?page=0&size=10&search=john&role=ROLE_USER
Authorization: Bearer <access_token>
```

**Query Parameters**:
- `page` (int, default=0): Số trang (bắt đầu từ 0)
- `size` (int, default=10): Số lượng records mỗi trang
- `search` (string, optional): Tìm kiếm theo username hoặc email
- `role` (string, optional): Lọc theo role (ROLE_USER, ROLE_ADMIN, ROLE_STAFF, ROLE_MANAGER)

**Required Permission**: `user:read`

**Response (200 OK)**:
```json
{
  "content": [
    {
      "id": 1,
      "email": "user@example.com",
      "username": "username",
      "roles": "ROLE_USER",
      "permissions": "user:create,user:update",
      "avatarUrl": "avatars/user-1/avatar.jpg"
    }
  ],
  "pageNumber": 0,
  "pageSize": 10,
  "totalElements": 25,
  "totalPages": 3,
  "last": false
}
```

#### 2.2. Get User by ID
```http
GET /api/users/{id}
Authorization: Bearer <access_token>
```

**Required Permission**: `user:read`

**Response (200 OK)**: Single user object

#### 2.3. Create User
```http
POST /api/users
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "email": "newuser@example.com",
  "username": "newuser",
  "password": "password123",
  "roles": "ROLE_USER",
  "permissions": "user:read"
}
```

**Required Permission**: `user:create`

**Response (201 Created)**: User object

#### 2.4. Update User
```http
PUT /api/users/{id}
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "email": "updated@example.com",
  "username": "updateduser",
  "roles": "ROLE_STAFF",
  "permissions": "user:read,user:create,order:read"
}
```

**Required Permission**: `user:update`

**Note**: 
- Không cần gửi `password` khi update (chỉ update khi muốn đổi password)
- `permissions`: Chuỗi các quyền cách nhau bởi dấu phẩy
- Auto-switch default avatar khi role thay đổi (nếu đang dùng default avatar)

**Response (200 OK)**: Updated user object

#### 2.5. Delete User
```http
DELETE /api/users/{id}
Authorization: Bearer <access_token>
```

**Required Permission**: `user:delete`

**Response (204 No Content)**

#### 2.6. Upload Avatar
```http
POST /api/users/{id}/avatar
Authorization: Bearer <access_token>
Content-Type: multipart/form-data

Form Data:
- file: [Image File] (max 10MB)
```

**Required Permission**: User chỉ có thể upload avatar của chính mình, trừ khi có ROLE_ADMIN

**Response (200 OK)**:
```json
{
  "message": "Avatar uploaded successfully",
  "avatarUrl": "avatars/user-1/uuid-abc123.jpg"
}
```

#### 2.7. Delete Avatar
```http
DELETE /api/users/{id}/avatar
Authorization: Bearer <access_token>
```

**Required Permission**: User chỉ có thể xóa avatar của chính mình, trừ khi có ROLE_ADMIN

**Response (200 OK)**:
```json
{
  "message": "Avatar deleted successfully",
  "avatarUrl": "avatars/default/user-avatar.png"
}
```

---

### 3. Role Management

#### 3.1. Get All Roles
```http
GET /api/roles
Authorization: Bearer <access_token>
```

**Required Permission**: `role:read`

**Response (200 OK)**:
```json
[
  {
    "id": 1,
    "name": "ROLE_ADMIN",
    "description": "Administrator with full access",
    "permissions": ["user:read", "user:create", "user:update", "user:delete", ...]
  },
  {
    "id": 2,
    "name": "ROLE_USER",
    "description": "Regular user",
    "permissions": ["user:read", "order:read", "order:create"]
  }
]
```

#### 3.2. Create Role
```http
POST /api/roles
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "name": "ROLE_MANAGER",
  "description": "Manager role with limited admin access",
  "permissions": ["user:read", "user:update", "order:read", "order:approve"]
}
```

**Required Permission**: `role:create`

**Response (201 Created)**: Role object

#### 3.3. Update Role
```http
PUT /api/roles/{id}
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "name": "ROLE_MANAGER",
  "description": "Updated description",
  "permissions": ["user:read", "user:update", "order:read", "order:approve", "report:read"]
}
```

**Required Permission**: `role:update`

**Response (200 OK)**: Updated role object

#### 3.4. Delete Role
```http
DELETE /api/roles/{id}
Authorization: Bearer <access_token>
```

**Required Permission**: `role:delete`

**Response (204 No Content)**

---

### 4. Permission Management

#### 4.1. Get All Permissions
```http
GET /api/permissions
Authorization: Bearer <access_token>
```

**Required Permission**: `permission:read`

**Response (200 OK)**:
```json
[
  {
    "id": 1,
    "name": "user:read",
    "description": "View user information",
    "category": "USER"
  },
  {
    "id": 2,
    "name": "user:create",
    "description": "Create new users",
    "category": "USER"
  },
  {
    "id": 3,
    "name": "order:approve",
    "description": "Approve orders",
    "category": "ORDER"
  }
]
```

**Permission Categories**:
- `USER` - User management permissions
- `ROLE` - Role management permissions
- `PERMISSION` - Permission management permissions
- `ORDER` - Order management permissions
- `REPORT` - Report management permissions
- `FILE` - File management permissions
- `AUDIT` - Audit log permissions

#### 4.2. Get Permissions by Category
```http
GET /api/permissions/category/{category}
Authorization: Bearer <access_token>
```

**Required Permission**: `permission:read`

**Example**: `GET /api/permissions/category/ORDER`

**Response (200 OK)**: Array of permissions in that category

---

## 📦 Order Service APIs

**Base URL via Gateway**: `http://localhost:8080/api/orders`

### 5. Order Management

#### 5.1. Get All Orders (Paginated)
```http
GET /api/orders?page=0&size=10&status=PENDING
Authorization: Bearer <access_token>
```

**Query Parameters**:
- `page` (int, default=0): Số trang
- `size` (int, default=10): Số lượng records
- `status` (string, optional): Filter by status (PENDING, APPROVED, REJECTED, COMPLETED)

**Required Permission**: `order:read`

**Response (200 OK)**:
```json
{
  "content": [
    {
      "id": 1,
      "orderNumber": "ORD-2024-0001",
      "description": "Order description",
      "amount": 1500000.00,
      "status": "PENDING",
      "createdBy": "user@example.com",
      "createdAt": "2024-01-15T10:30:00",
      "approvedBy": null,
      "approvedAt": null
    }
  ],
  "pageNumber": 0,
  "pageSize": 10,
  "totalElements": 50,
  "totalPages": 5,
  "last": false
}
```

#### 5.2. Create Order
```http
POST /api/orders
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "description": "Purchase office supplies",
  "amount": 2500000.00,
  "items": [
    {
      "productName": "Laptop Dell XPS",
      "quantity": 1,
      "unitPrice": 2500000.00
    }
  ]
}
```

**Required Permission**: `order:create`

**Response (201 Created)**: Order object

#### 5.3. Approve Order
```http
POST /api/orders/{id}/approve
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "approvalNote": "Approved for purchase"
}
```

**Required Permission**: `order:approve`

**Response (200 OK)**: Updated order with status APPROVED

#### 5.4. Reject Order
```http
POST /api/orders/{id}/reject
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "rejectionReason": "Budget exceeded"
}
```

**Required Permission**: `order:approve`

**Response (200 OK)**: Updated order with status REJECTED

---

### 6. Report Management

#### 6.1. Get All Reports
```http
GET /api/reports?page=0&size=10&type=MONTHLY
Authorization: Bearer <access_token>
```

**Query Parameters**:
- `page`, `size`: Pagination
- `type` (optional): DAILY, WEEKLY, MONTHLY, QUARTERLY, YEARLY

**Required Permission**: `report:read`

**Response (200 OK)**: Paginated list of reports

#### 6.2. Export Report
```http
POST /api/reports/{id}/export
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "format": "PDF"
}
```

**Required Permission**: `report:export`

**Supported Formats**: PDF, EXCEL, CSV

**Response (200 OK)**:
```json
{
  "downloadUrl": "http://localhost:8080/api/files/download/reports/report-123.pdf",
  "expiresAt": "2024-01-15T18:00:00"
}
```

---

## 📁 File Service APIs

**Base URL via Gateway**: `http://localhost:8080/api/files`

### 7. File Management

#### 7.1. Upload File
```http
POST /api/files/upload
Authorization: Bearer <access_token>
Content-Type: multipart/form-data

Form Data:
- file: [File] (max 100MB)
- folder: "documents" (optional, default: "general")
```

**Required Permission**: `file:upload`

**Response (200 OK)**:
```json
{
  "fileName": "uuid-abc123_document.pdf",
  "fileUrl": "documents/uuid-abc123_document.pdf",
  "fileSize": 2048576,
  "contentType": "application/pdf",
  "uploadedAt": "2024-01-15T10:30:00"
}
```

#### 7.2. Download File
```http
GET /api/files/download/{folder}/{filename}
Authorization: Bearer <access_token>
```

**Example**: `GET /api/files/download/documents/report.pdf`

**Required Permission**: `file:download`

**Response (200 OK)**: File content with appropriate content-type header

#### 7.3. Get Presigned URL
```http
GET /api/files/url/{folder}/{filename}
Authorization: Bearer <access_token>
```

**Required Permission**: `file:read`

**Response (200 OK)**:
```json
{
  "url": "http://localhost:9000/files/documents/report.pdf?X-Amz-Algorithm=...",
  "expiresIn": 3600
}
```

#### 7.4. Delete File
```http
DELETE /api/files/{folder}/{filename}
Authorization: Bearer <access_token>
```

**Required Permission**: `file:delete`

**Response (200 OK)**: `"File deleted successfully"`

#### 7.5. Get File Metadata
```http
GET /api/files/metadata/{folder}/{filename}
Authorization: Bearer <access_token>
```

**Required Permission**: `file:read`

**Response (200 OK)**:
```json
{
  "fileName": "report.pdf",
  "fileSize": 2048576,
  "contentType": "application/pdf",
  "lastModified": "2024-01-15T10:30:00"
}
```

#### 7.6. Check File Existence
```http
GET /api/files/exists/{folder}/{filename}
Authorization: Bearer <access_token>
```

**Required Permission**: `file:read`

**Response (200 OK)**:
```json
{
  "exists": true
}
```

---

## 🔑 Permission System

### Permission Format
Format: `{RESOURCE}:{ACTION}`
- **Resource**: UPPERCASE singular noun (USER, ORDER, REPORT)
- **Action**: lowercase verb (read, create, update, delete, approve, export)

### Available Permissions

#### User Permissions
- `user:read` - View users
- `user:create` - Create new users
- `user:update` - Update user information
- `user:delete` - Delete users

#### Role Permissions
- `role:read` - View roles
- `role:create` - Create new roles
- `role:update` - Update roles
- `role:delete` - Delete roles

#### Permission Permissions
- `permission:read` - View permissions
- `permission:create` - Create permissions
- `permission:update` - Update permissions
- `permission:delete` - Delete permissions

#### Order Permissions
- `order:read` - View orders
- `order:create` - Create orders
- `order:update` - Update orders
- `order:delete` - Delete orders
- `order:approve` - Approve/reject orders

#### Report Permissions
- `report:read` - View reports
- `report:create` - Create reports
- `report:export` - Export reports to PDF/Excel

#### File Permissions
- `file:read` - View file metadata and URLs
- `file:upload` - Upload files
- `file:download` - Download files
- `file:delete` - Delete files

#### Audit Permissions
- `audit:read` - View audit logs
- `audit:create` - Create audit entries

### Default Role Permissions

**ROLE_ADMIN** (Full access):
- All permissions from all categories

**ROLE_MANAGER**:
- User: read, update
- Order: read, create, update, approve
- Report: read, export
- File: read, upload, download

**ROLE_STAFF**:
- User: read
- Order: read, create
- Report: read
- File: read, upload, download

**ROLE_USER**:
- User: read (own profile only)
- Order: read, create (own orders)
- File: read, download (own files)

---

## 🏗️ Architecture & Tech Stack

### Technology Stack
- **Backend**: Spring Boot 3.x, Java 17
- **Security**: Spring Security, JWT
- **Database**: PostgreSQL
- **Cache**: Redis
- **Storage**: MinIO (S3-compatible)
- **Gateway**: Spring Cloud Gateway
- **API Documentation**: Swagger/OpenAPI

### Database Schema

#### User Table
```sql
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    roles VARCHAR(100),
    permissions TEXT,
    avatar_url VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### Role Table
```sql
CREATE TABLE roles (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### Permission Table
```sql
CREATE TABLE permissions (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description VARCHAR(255),
    category VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## 🚀 Quick Start Guide

### 1. Setup với Docker
```bash
cd java
docker-compose up -d
```

Services will start on:
- API Gateway: http://localhost:8080
- Auth Service: http://localhost:8081
- Order Service: http://localhost:8082
- File Service: http://localhost:8083
- MinIO Console: http://localhost:9001

### 2. Default Admin Account
```json
{
  "email": "admin@admin.com",
  "password": "admin123"
}
```

### 3. Test API with cURL

**Register**:
```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","username":"testuser","password":"test123"}'
```

**Login**:
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"emailOrUsername":"test@test.com","password":"test123"}'
```

**Get Profile**:
```bash
curl -X GET http://localhost:8080/api/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

---

## ❗ Error Responses

### Standard Error Format
```json
{
  "timestamp": "2024-01-15T10:30:00",
  "status": 400,
  "error": "Bad Request",
  "message": "Email already exists",
  "path": "/api/auth/register"
}
```

### Common HTTP Status Codes
- `200` OK - Request thành công
- `201` Created - Resource được tạo thành công
- `204` No Content - Request thành công, không có data trả về
- `400` Bad Request - Request không hợp lệ
- `401` Unauthorized - Chưa đăng nhập hoặc token không hợp lệ
- `403` Forbidden - Không có quyền truy cập
- `404` Not Found - Resource không tồn tại
- `409` Conflict - Conflict (e.g., email đã tồn tại)
- `500` Internal Server Error - Lỗi server

---

## 📚 Additional Documentation

- [Permission Guide](PERMISSION_GUIDE.md) - Hướng dẫn thêm permissions mới
- [Avatar Guide](AVATAR_GUIDE.md) - Hướng dẫn sử dụng avatar feature
- [Frontend Integration](FRONTEND_INTEGRATION.md) - Tích hợp với Frontend
- [Database Migration](DATABASE_MIGRATION.md) - Migration guide
- [Order Service README](order-service/README.md) - Chi tiết Order Service
- [File Service README](file-service/README.md) - Chi tiết File Service

---

## 🔧 Environment Variables

### Auth Service
```env
JWT_SECRET=your-super-secret-key-min-256-bits
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/auth_db
SPRING_REDIS_HOST=localhost
SPRING_REDIS_PORT=6379
```

### File Service
```env
MINIO_ENDPOINT=http://localhost:9000
MINIO_ACCESS_KEY=minioadmin
MINIO_SECRET_KEY=minioadmin123
MINIO_BUCKET_NAME=files
```

---

## 📞 Support & Contact

For issues or questions:
- Create an issue in the repository
- Contact: ducbmt@example.com

---

**Last Updated**: February 17, 2026
**Version**: 1.0.0
