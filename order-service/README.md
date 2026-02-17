# Order Service

Service quản lý đơn hàng (orders) và báo cáo (reports) trong hệ thống microservices.

## Cổng

- **Port**: 8082
- **Database**: PostgreSQL (order_db) - Port 5433

## Endpoints

### Order Management

#### 1. Lấy danh sách đơn hàng
```bash
GET /api/orders?page=0&size=10&status=pending
Authorization: Bearer <access_token>
Permissions: ADMIN or order:read
```

#### 2. Tạo đơn hàng mới
```bash
POST /api/orders
Authorization: Bearer <access_token>
Content-Type: application/json
Permissions: ADMIN or order:create

{
  "customerName": "John Doe",
  "amount": 100.50
}
```

#### 3. Cập nhật đơn hàng
```bash
PUT /api/orders/{id}
Authorization: Bearer <access_token>
Content-Type: application/json
Permissions: ADMIN or order:update

{
  "customerName": "Jane Smith",
  "amount": 250.75
}
```

#### 4. Phê duyệt đơn hàng
```bash
POST /api/orders/{id}/approve
Authorization: Bearer <access_token>
Permissions: ADMIN or order:approve
```

#### 5. Từ chối đơn hàng
```bash
POST /api/orders/{id}/reject
Authorization: Bearer <access_token>
Content-Type: application/json
Permissions: ADMIN or order:approve

{
  "reason": "Out of stock"
}
```

#### 6. Xóa đơn hàng
```bash
DELETE /api/orders/{id}
Authorization: Bearer <access_token>
Permissions: order:delete
```

### Report Management

#### 1. Lấy danh sách báo cáo
```bash
GET /api/reports?page=0&size=10
Authorization: Bearer <access_token>
Permissions: ADMIN or report:read
```

#### 2. Tạo báo cáo mới
```bash
POST /api/reports
Authorization: Bearer <access_token>
Content-Type: application/json
Permissions: ADMIN or report:create

{
  "name": "Monthly Sales Report",
  "type": "sales"
}
```

#### 3. Cập nhật báo cáo
```bash
PUT /api/reports/{id}
Authorization: Bearer <access_token>
Content-Type: application/json
Permissions: ADMIN or report:update

{
  "name": "Updated Report Name"
}
```

#### 4. Xóa báo cáo
```bash
DELETE /api/reports/{id}
Authorization: Bearer <access_token>
Permissions: ADMIN or report:delete
```

#### 5. Export báo cáo
```bash
POST /api/reports/{id}/export
Authorization: Bearer <access_token>
Permissions: ADMIN or report:export
```

## Chạy Service

### Chạy độc lập (Development)
```bash
cd order-service
mvn clean install
mvn spring-boot:run -Dspring-boot.run.profiles=local
```

### Chạy với Docker Compose
```bash
cd java
docker-compose up order-service
```

## Kiến trúc

```
Client Request
    ↓
API Gateway (8080)
    ↓
Order Service (8082) - JWT Validation
    ↓
PostgreSQL (order_db)
```

## Lưu ý

- Order Service **không** tạo JWT, chỉ validate token từ Auth Service
- Tất cả requests phải đi qua API Gateway
- JWT Secret phải giống với Auth Service
- Database riêng biệt (order_db) để đảm bảo tách biệt dữ liệu
