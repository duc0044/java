# Tài liệu kết nối Frontend - Backend

Dưới đây là hướng dẫn chi tiết để Frontend (FE) tích hợp với hệ thống microservices hiện tại.

## 1. Thông tin chung
- **Base URL (API Gateway)**: `http://localhost:8080`
- **Tất cả request** gửi từ FE phải đi qua Gateway này.

## 2. Luồng Xác thực (Authentication)

### A. Đăng ký / Đăng nhập thủ công
| Chức năng | Method | Endpoint | Request Body |
| :--- | :--- | :--- | :--- |
| **Đăng ký** | `POST` | `/api/auth/register` | `{"email", "username", "password"}` |
| **Đăng nhập** | `POST` | `/api/auth/login` | `{"email", "password"}` |

**Kết quả trả về (AuthResponse):**
```json
{
  "accessToken": "ey...",
  "refreshToken": "ey...",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "username": "user123",
    "roles": "ROLE_USER",
    "permissions": null
  }
}
```

### B. Đăng nhập qua Google (OAuth2)
FE không dùng Axios để gọi API này mà dùng link trực tiếp (hoặc `window.location.href`):

1. **Trigger Google Login**: 
   Khi người dùng bấm nút "Login with Google", chuyển hướng trình duyệt đến:
   `http://localhost:8080/api/auth/oauth2/authorization/google`

2. **Xử lý Callback**:
   Sau khi Google xác thực thành công, Backend sẽ redirect về:
   `http://localhost:3000/auth/callback?accessToken=...&refreshToken=...`
   
   FE cần viết code tại page `/auth/callback` để:
   - Lấy `accessToken` và `refreshToken` từ URL query parameters.
   - Lưu vào `localStorage` hoặc `cookie`.
   - Chuyển hướng người dùng vào trang chủ Dashboard.

### C. Dashboard & Profile API
Mọi request này yêu cầu đính kèm `accessToken` vào Authorization header.

| Chức năng | Method | Endpoint | Quyền hạn |
| :--- | :--- | :--- | :--- |
| **Lấy Profile** | `GET` | `/api/auth/me` | Mọi user |
| **Thống kê Dash** | `GET` | `/api/auth/dashboard/summary` | Chỉ ADMIN |

**Kết quả trả về Thống kê Dashboard:**
```json
{
  "totalUsers": 10,
  "activeSessions": 5,
  "systemHealth": "Excellent",
  "recentActivity": ["...", "..."]
}
```

## 3. Phân quyền (Roles)
- Hệ thống hỗ trợ 2 roles mặc định: `ROLE_USER` và `ROLE_ADMIN`.
- Cần có `ROLE_ADMIN` để truy cập các endpoint thống kê hệ thống.

## 4. Phân quyền chi tiết (Granular & Dynamic)
Hệ thống sử dụng cơ chế **Dynamic Permission**: Quyền hạn của user là tập hợp của `Quyền theo Role` + `Quyền riêng lẻ (Direct Permissions)`.

| Chức năng | Method | Endpoint | Quyền hạn (Authority) |
| :--- | :--- | :--- | :--- |
| **Xem danh sách** | `GET` | `/api/users` | `user:read` |
| **Tạo mới** | `POST` | `/api/users` | `user:create` |
| **Cập nhật** | `PUT` | `/api/users/{id}` | `user:update` |
| **Xóa** | `DELETE` | `/api/users/{id}` | `user:delete` |

**Cập nhật Quyền hạn (Admin Only):**
API `PUT /api/users/{id}` hỗ trợ cập nhật `roles` và `permissions`.
- Body: `{"roles": "ROLE_STAFF", "permissions": "user:create,user:update"}`
- `permissions`: Chuỗi các quyền cách nhau bởi dấu phẩy.

### Query Parameters for GET `/api/users` (Pagination & Filter)
| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `page` | `int` | `0` | Số trang (bắt đầu từ 0) |
| `size` | `int` | `10` | Số lượng bản ghi mỗi trang |
| `search` | `string` | | Tìm kiếm theo `username` hoặc `email` (không phân biệt hoa thường) |
| `role` | `string` | | Lọc theo role (VD: `ROLE_ADMIN`, `ROLE_USER`) |

**Định dạng kết quả trả về (PageResponse):**
```json
{
  "content": [
    { "id": 1, "email": "...", "username": "...", "roles": "ROLE_USER", "permissions": null },
    { "id": 2, "email": "...", "username": "...", "roles": "ROLE_STAFF", "permissions": "user:create" }
  ],
  "pageNumber": 0,
  "pageSize": 10,
  "totalElements": 2,
  "totalPages": 1,
  "last": true
}
```

**Mapping mặc định (Role-based):**
- `ROLE_USER`: Chỉ có `user:read`.
- `ROLE_STAFF`: Mặc định chỉ có `user:read`, `user:update`. (Muốn có `user:create` phải gán thêm permission riêng).
- `ROLE_ADMIN`: Có toàn bộ `user:read`, `user:create`, `user:update`, `user:delete`.

## 5. Quản lý Token (Best Practice)

### Authorization Header
Mọi request cần xác thực phải kèm header:
`Authorization: Bearer <accessToken>`

### Cơ chế Refresh Token
Khi `accessToken` hết hạn (lỗi 401), FE hãy gọi API sau để lấy token mới:
- **Endpoint**: `POST /api/auth/refresh`
- **Body**: `{"refreshToken": "..."}`

### Ví dụ Axios Interceptor (Javascript/Typescript)
```javascript
import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8080',
});

// Gắn token vào request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('accessToken');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Tự động refresh khi hết hạn
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response.status === 401) {
      const refreshToken = localStorage.getItem('refreshToken');
      const res = await axios.post('http://localhost:8080/api/auth/refresh', { refreshToken });
      localStorage.setItem('accessToken', res.data.accessToken);
      return api(error.config); // Gửi lại request cũ
    }
    return Promise.reject(error);
  }
);
```

## 6. Ví dụ kịch bản phân quyền (Scenarios)

### Kịch bản 1: Tạo nhân viên Sales (Chỉ xem)
**Bước 1**: Admin tạo user hoặc user tự đăng ký.
**Bước 2**: Admin set role là `ROLE_STAFF`.
**Kết quả**: User này mặc định có quyền `user:read`, `user:update`. (Theo code AuthorityUtils).

### Kịch bản 2: Nhân viên quản lý nhân sự (Cần thêm quyền tạo mới)
Nhân viên A (`id=10`) đang là `ROLE_STAFF`. Admin muốn cho phép người này tạo user mới (mặc định Staff không có quyền này).

**Request (Admin gọi):**
```http
PUT /api/users/10
Content-Type: application/json
Authorization: Bearer <admin_token>

{
  "permissions": "user:create"
}
```

**Kết quả**:
- User A khi đăng nhập sẽ có authorities: `user:read`, `user:update` (từ Role) + `user:create` (riêng).
- User A gọi `POST /api/users` -> **Thành công**.

### Kịch bản 3: Thu hồi quyền
Nếu muốn thu hồi quyền tạo mới của User A, Admin gửi `permissions` là rỗng hoặc null.

```http
PUT /api/users/10
{
  "permissions": ""
}
```
User A trở về quyền mặc định của `ROLE_STAFF`.
