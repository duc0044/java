# File Service

Service quản lý file storage với MinIO trong hệ thống microservices.

## Cổng

- **Port**: 8083
- **MinIO Console**: http://localhost:9001 (minioadmin/minioadmin123)
- **MinIO API**: http://localhost:9000

## Tính năng

- ✅ Upload files (hỗ trợ đến 100MB)
- ✅ Download files
- ✅ Generate presigned URLs (temporary access)
- ✅ Delete files (chỉ Admin hoặc có quyền file:delete)
- ✅ Get file metadata
- ✅ Check file existence
- ✅ Tự động tạo bucket
- ✅ JWT authentication
- ✅ Permission-based access control

## Endpoints

### 1. Upload File
```bash
POST /api/files/upload
Authorization: Bearer <access_token>
Content-Type: multipart/form-data

Form Data:
- file: [File]
- folder: general (optional, default: "general")
```

**Response:**
```json
{
  "fileName": "general/uuid-123.jpg",
  "fileUrl": "/api/files/download/general/uuid-123.jpg",
  "contentType": "image/jpeg",
  "size": 102400,
  "uploadedBy": "user@example.com",
  "uploadedAt": "2026-02-15T10:30:00"
}
```

### 2. Download File
```bash
GET /api/files/download/{folder}/{filename}
Authorization: Bearer <access_token>
```

### 3. Get Presigned URL (Temporary Access)
```bash
GET /api/files/url/{folder}/{filename}?expiry=60
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "url": "http://minio:9000/files/general/uuid-123.jpg?X-Amz-Algorithm=...",
  "expiresInMinutes": "60"
}
```

### 4. Delete File
```bash
DELETE /api/files/{folder}/{filename}
Authorization: Bearer <access_token>
Permissions: ADMIN or file:delete
```

### 5. Get File Metadata
```bash
GET /api/files/metadata/{folder}/{filename}
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "fileName": "general/uuid-123.jpg",
  "size": 102400,
  "contentType": "image/jpeg",
  "lastModified": "2026-02-15T10:30:00Z",
  "etag": "d41d8cd98f00b204e9800998ecf8427e"
}
```

### 6. Check File Exists
```bash
GET /api/files/exists/{folder}/{filename}
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "exists": true
}
```

## Folders Organization

Files được tổ chức theo thư mục:
- `general/` - Files chung
- `documents/` - Documents (PDF, Word, etc.)
- `images/` - Images
- `videos/` - Videos
- `avatars/` - User avatars
- `reports/` - Report files

## Usage Examples

### Upload với cURL
```bash
curl -X POST http://localhost:8080/api/files/upload \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@/path/to/file.jpg" \
  -F "folder=images"
```

### Upload với JavaScript/Axios
```javascript
const formData = new FormData();
formData.append('file', fileInput.files[0]);
formData.append('folder', 'images');

axios.post('http://localhost:8080/api/files/upload', formData, {
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'multipart/form-data'
  }
});
```

### Download File
```bash
curl -X GET http://localhost:8080/api/files/download/images/uuid-123.jpg \
  -H "Authorization: Bearer YOUR_TOKEN" \
  --output downloaded-file.jpg
```

## MinIO Configuration

### Default Settings
- **Username**: minioadmin
- **Password**: minioadmin123
- **Bucket**: files
- **Auto-create bucket**: true

### Environment Variables
```bash
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=minioadmin123
MINIO_BUCKET=files
```

### Access MinIO Console
1. Open http://localhost:9001
2. Login với minioadmin/minioadmin123
3. Xem và quản lý files, buckets, users, policies

## Permissions Required

- **Upload**: Authenticated users
- **Download**: Authenticated users
- **Get URL**: Authenticated users
- **Metadata**: Authenticated users
- **Check exists**: Authenticated users
- **Delete**: `ROLE_ADMIN` hoặc `file:delete`

## File Size Limits

- **Max file size**: 100MB
- **Max request size**: 100MB

Có thể điều chỉnh trong [application.yml](src/main/resources/application.yml):
```yaml
server:
  servlet:
    multipart:
      max-file-size: 100MB
      max-request-size: 100MB
```

## Chạy Service

### Chạy độc lập (Development)
```bash
cd file-service
mvn clean install
mvn spring-boot:run -Dspring-boot.run.profiles=local
```

### Chạy với Docker Compose
```bash
cd java
docker-compose up file-service minio
```

## Kiến trúc

```
Client Request
    ↓
API Gateway (8080)
    ↓
File Service (8083) - JWT Validation
    ↓
MinIO (9000) - Object Storage
```

## Lưu ý

- File Service **không** tạo JWT, chỉ validate token từ Auth Service
- Tất cả requests phải đi qua API Gateway
- JWT Secret phải giống với Auth Service
- Files được lưu persistent trong Docker volume `minio_data`
- File names được generate unique bằng UUID để tránh trùng lặp
