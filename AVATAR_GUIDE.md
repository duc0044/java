# Avatar Feature Guide

## Overview

Auth service hỗ trợ avatar cho users với các tính năng:
- ✅ Upload custom avatar
- ✅ Default avatar tự động theo role (Admin/User)
- ✅ Delete avatar
- ✅ Avatar được lưu theo User ID trong MinIO

## Default Avatars

Hệ thống tự động set avatar mặc định khi tạo user mới:

### Admin Users
- **Default Avatar**: `avatars/default/admin-avatar.png`
- Tự động được set khi:
  - User mới được tạo với ROLE_ADMIN
  - User được promote lên ROLE_ADMIN (nếu đang dùng default user avatar)

### Regular Users
- **Default Avatar**: `avatars/default/user-avatar.png`
- Tự động được set khi:
  - User mới đăng ký (register)
  - User mới được tạo với ROLE_USER
  - User bị demote từ ROLE_ADMIN (nếu đang dùng default admin avatar)

### Configuration

Default avatars được config trong `application.yml`:

```yaml
avatar:
  default:
    admin: avatars/default/admin-avatar.png
    user: avatars/default/user-avatar.png
```

### Setup Default Avatar Files

**Bước 1: Upload default avatar images vào MinIO**

```bash
# Via File Service API
curl -X POST http://localhost:8080/api/files/upload \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -F "file=@admin-avatar.png" \
  -F "folder=avatars/default"

curl -X POST http://localhost:8080/api/files/upload \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -F "file=@user-avatar.png" \
  -F "folder=avatars/default"
```

**Bước 2: Hoặc upload trực tiếp qua MinIO Console**

1. Truy cập http://localhost:9001
2. Login với minioadmin/minioadmin123
3. Vào bucket `files`
4. Tạo folder `avatars/default/`
5. Upload `admin-avatar.png` và `user-avatar.png`

**Note:** Đảm bảo tên file khớp với config trong `application.yml`

### Auto Avatar Switching

Hệ thống tự động chuyển đổi avatar khi role thay đổi:

**Promoted to Admin:**
```
User has: ROLE_USER + default-user-avatar.png
→ Admin assigns ROLE_ADMIN
→ Avatar auto-updates to: default-admin-avatar.png
```

**Demoted from Admin:**
```
User has: ROLE_ADMIN + default-admin-avatar.png
→ Admin removes ROLE_ADMIN
→ Avatar auto-updates to: default-user-avatar.png
```

**Custom Avatar Protection:**
```
User has: ROLE_USER + custom-uploaded-avatar.jpg
→ Admin assigns ROLE_ADMIN
→ Avatar remains: custom-uploaded-avatar.jpg (no change)
```

**Important:** Auto-switching chỉ áp dụng cho default avatars. Custom uploaded avatars được giữ nguyên khi role thay đổi.

## Database Schema

### User Table
```sql
ALTER TABLE users ADD COLUMN avatar_url VARCHAR(500);
```

Trường `avatar_url` lưu đường dẫn file trong MinIO (ví dụ: `avatars/user-1/uuid-123.jpg`).

**Note:** Avatar được tổ chức theo User ID để dễ quản lý:
- User ID 1: `avatars/user-1/`
- User ID 2: `avatars/user-2/`
- User ID 123: `avatars/user-123/`

## API Endpoints

### 1. Upload Avatar

**Endpoint:** `POST /api/users/{id}/avatar`

**Authorization:** Bearer token (user phải upload avatar của chính mình hoặc có ADMIN role)

**Request:**
```bash
curl -X POST http://localhost:8080/api/users/1/avatar \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@/path/to/avatar.jpg"
```

**Response:**
```json
{
  "avatarUrl": "avatars/user-1/uuid-123.jpg",
  "fileName": "avatars/user-1/uuid-123.jpg",
  "message": "Avatar uploaded successfully"
}
```

**Business Logic:**
1. Kiểm tra quyền (own avatar hoặc ADMIN)
2. Xóa avatar cũ (nếu có) từ MinIO
3. Upload avatar mới vào folder `avatars/user-{userId}/` trong MinIO
4. Cập nhật `avatar_url` trong database
5. Trả về URL của avatar mới

**Folder Structure:**
- Mỗi user có folder riêng: `avatars/user-{userId}/`
- Ví dụ:
  - User ID 1: `avatars/user-1/abc123.jpg`
  - User ID 5: `avatars/user-5/def456.png`
  - User ID 100: `avatars/user-100/xyz789.jpg`
- Filename được generate bằng UUID để tránh trùng lặp

**File Restrictions:**
- Max file size: 10MB
- Recommended formats: JPG, PNG, GIF
- Files stored in MinIO bucket: `files/avatars/`

### 2. Delete Avatar

**Endpoint:** `DELETE /api/users/{id}/avatar`

**Authorization:** Bearer token (user phải xóa avatar của chính mình hoặc có ADMIN role)

**Request:**
```bash
curl -X DELETE http://localhost:8080/api/users/1/avatar \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response:** `204 No Content`

**Business Logic:**
1. Kiểm tra quyền (own avatar hoặc ADMIN)
2. Xóa file từ MinIO thông qua file-service
3. Set `avatar_url = null` trong database

### 3. Get User Info (with Avatar)

**Endpoint:** `GET /api/users/{id}`

**Response:**
```json
{
  "id": 1,
  "email": "user@example.com",
  "username": "john_doe",
  "avatarUrl": "avatars/user-1/uuid-123.jpg",
  "roles": ["ROLE_USER"],
  "permissions": ["order:read", "order:create"]
}
```

**Note:** `avatarUrl` sẽ là `null` nếu user chưa upload avatar.

### 4. Login/Register Response (with Avatar)

Khi login hoặc register thành công, response cũng bao gồm avatar:

**New User (with default avatar):**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1...",
  "refreshToken": "eyJhbGciOiJIUzI1...",
  "tokenType": "Bearer",
  "expiresIn": 900000,
  "user": {
    "id": 1,
    "email": "user@example.com",
    "username": "john_doe",
    "avatarUrl": "avatars/default/user-avatar.png",
    "roles": ["ROLE_USER"],
    "permissions": []
  }
}
```

**Admin User (with default admin avatar):**
```json
{
  "user": {
    "id": 2,
    "email": "admin@example.com",
    "username": "admin",
    "avatarUrl": "avatars/default/admin-avatar.png",
    "roles": ["ROLE_ADMIN"],
    "permissions": ["user:read", "user:create", "..."]
  }
}
```

**User with custom avatar:**
```json
{
  "user": {
    "id": 3,
    "email": "custom@example.com",
    "username": "custom_user",
    "avatarUrl": "avatars/user-3/uuid-123.jpg",
    "roles": ["ROLE_USER"],
    "permissions": []
  }
}
```

## Integration with File Service

Auth service tích hợp với file-service thông qua `FileServiceClient`:

```java
@Component
public class FileServiceClient {
    // Upload file to file-service
    public String uploadFile(MultipartFile file, String folder, String token)
    
    // Delete file from file-service  
    public void deleteFile(String filePath, String token)
}
```

**Configuration:**
```yaml
# application.yml
file-service:
  url: http://file-service:8083  # Docker
  # url: http://localhost:8083   # Local
```

## Frontend Integration Examples

### React + Axios

```javascript
// Upload avatar
const uploadAvatar = async (userId, file) => {
  const formData = new FormData();
  formData.append('file', file);
  
  const response = await axios.post(
    `http://localhost:8080/api/users/${userId}/avatar`,
    formData,
    {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'multipart/form-data'
      }
    }
  );
  
  return response.data;
};

// Display avatar
const AvatarImage = ({ user }) => {
  const avatarUrl = user.avatarUrl 
    ? `http://localhost:8080/api/files/download/${user.avatarUrl}`
    : '/default-avatar.png';
    
  return <img src={avatarUrl} alt="Avatar" />;
};

// Delete avatar
const deleteAvatar = async (userId) => {
  await axios.delete(
    `http://localhost:8080/api/users/${userId}/avatar`,
    {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    }
  );
};
```

### HTML + JavaScript

```html
<!-- Upload form -->
<form id="avatarForm">
  <input type="file" name="avatar" accept="image/*" />
  <button type="submit">Upload Avatar</button>
</form>

<script>
document.getElementById('avatarForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const formData = new FormData(e.target);
  
  const response = await fetch(`/api/users/${userId}/avatar`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`
    },
    body: formData
  });
  
  const data = await response.json();
  console.log('Avatar uploaded:', data.avatarUrl);
});
</script>
```

## Display Avatar URLs

Avatar URL trả về là relative path (ví dụ: `avatars/user-1/uuid-123.jpg`).

**Cách display:**

### Option 1: Qua File Service Download Endpoint
```
GET http://localhost:8080/api/files/download/avatars/user-1/uuid-123.jpg
```

### Option 2: Qua MinIO Presigned URL
```javascript
// Get presigned URL (60 minutes expiry)
const response = await axios.get(
  `http://localhost:8080/api/files/url/avatars/user-1/uuid-123.jpg?expiry=60`,
  {
    headers: { 'Authorization': `Bearer ${token}` }
  }
);

const presignedUrl = response.data.url;
// Use this URL in <img src={presignedUrl} />
```

## Security

1. **Authentication Required**: Tất cả avatar endpoints yêu cầu JWT token
2. **Authorization**: 
   - Users chỉ có thể upload/delete avatar của chính mình
   - ADMIN có thể upload/delete avatar của bất kỳ user nào
3. **File Validation**: 
   - Max size: 10MB (có thể config trong application.yml)
   - Nên validate file type ở frontend trước khi upload
4. **Auto Cleanup**: Khi upload avatar mới, avatar cũ sẽ tự động bị xóa

## Database Migration

Nếu database đã tồn tại, chạy migration sau:

```sql
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url VARCHAR(500);
```

JPA sẽ tự động tạo column này khi start service nếu `ddl-auto: update`.

## Testing

### Test Upload Avatar
```bash
# Get token first
TOKEN=$(curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"emailOrUsername":"admin@test.com","password":"admin123"}' \
  | jq -r '.accessToken')

# Upload avatar
curl -X POST http://localhost:8080/api/users/1/avatar \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@avatar.jpg"
```

### Test Get User with Avatar
```bash
curl -X GET http://localhost:8080/api/users/1 \
  -H "Authorization: Bearer $TOKEN"
```

### Test Delete Avatar
```bash
curl -X DELETE http://localhost:8080/api/users/1/avatar \
  -H "Authorization: Bearer $TOKEN"
```

## Troubleshooting

### Error: "Failed to upload file"
- Kiểm tra file-service có đang chạy không
- Kiểm tra MinIO có đang chạy không
- Kiểm tra `file-service.url` config trong auth-service

### Error: "Missing authentication token"
- Đảm bảo gửi `Authorization: Bearer <token>` header

### Error: "Bạn không có quyền upload avatar cho user này"
- User chỉ có thể upload avatar của chính mình
- Hoặc cần ADMIN role để upload cho user khác

### Avatar không hiển thị
- Kiểm tra URL có đúng format không
- Kiểm tra file-service có khả dụng không
- Thử download trực tiếp từ file-service endpoint
