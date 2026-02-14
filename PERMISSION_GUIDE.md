# Hướng dẫn thêm Permission và Feature mới

## 🚀 Quy trình thêm feature/permission mới

### **Bước 1: Thêm Permission Constants**
**File**: `auth-service/src/main/java/com/auth/entity/Permission.java`

```java
// Thêm permissions cho feature mới theo pattern: RESOURCE:ACTION
public static final String PRODUCT_READ = "product:read";
public static final String PRODUCT_CREATE = "product:create";
public static final String PRODUCT_UPDATE = "product:update";
public static final String PRODUCT_DELETE = "product:delete";
```

**Naming Convention:**
- Format: `{RESOURCE}:{ACTION}`
- Resource: danh từ số ít, viết hoa (USER, ORDER, REPORT)
- Action: động từ viết thường (read, create, update, delete, approve, export)

### **Bước 2: Cập nhật Role-Permission Mapping**
**File**: `auth-service/src/main/java/com/auth/util/AuthorityUtils.java`

```java
static {
    ROLE_PERMISSIONS.put("ROLE_ADMIN", Arrays.asList(
        // Existing permissions...
        // New feature permissions
        Permission.PRODUCT_READ, Permission.PRODUCT_CREATE,
        Permission.PRODUCT_UPDATE, Permission.PRODUCT_DELETE
    ));
    
    ROLE_PERMISSIONS.put("ROLE_STAFF", Arrays.asList(
        // Give appropriate permissions based on business logic
        Permission.PRODUCT_READ, Permission.PRODUCT_CREATE, Permission.PRODUCT_UPDATE
    ));
}
```

**Cập nhật methods:**
- `getAllPermissions()` - thêm permissions mới
- `getPermissionsByCategory()` - thêm category mới

### **Bước 3: Cập nhật Validation**
**File**: `auth-service/src/main/java/com/auth/service/AuthService.java`

Thêm validation cho permissions mới trong `validatePermissions()`:
```java
Set<String> validPermissions = Set.of(
    // Existing permissions...
    Permission.PRODUCT_READ, Permission.PRODUCT_CREATE,
    Permission.PRODUCT_UPDATE, Permission.PRODUCT_DELETE
);
```

### **Bước 4: Tạo Controller cho Feature mới**
**File**: `auth-service/src/main/java/com/auth/controller/{FeatureName}Controller.java`

```java
@RestController
@RequestMapping("/api/products")
public class ProductController {

    @GetMapping
    @PreAuthorize("hasAuthority('product:read')")
    public ResponseEntity<List<Product>> getAllProducts() {
        // Implementation
    }

    @PostMapping
    @PreAuthorize("hasAuthority('product:create')")
    public ResponseEntity<Product> createProduct(@RequestBody ProductRequest request) {
        // Implementation
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('product:update')")
    public ResponseEntity<Product> updateProduct(@PathVariable Long id, @RequestBody ProductRequest request) {
        // Implementation
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('product:delete')")
    public ResponseEntity<Void> deleteProduct(@PathVariable Long id) {
        // Implementation
    }
}
```

### **Bước 5: Cập nhật API Gateway Routes**
**Files**: 
- `api-gateway/src/main/resources/application.yml` (Docker)
- `api-gateway/src/main/resources/application-local.yml` (Local)

```yaml
routes:
  # Existing routes...
  - id: auth-service-products
    uri: http://localhost:8081  # hoặc http://auth-service:8081 cho Docker
    predicates:
      - Path=/api/products/**,/api/products
    filters:
      - StripPrefix=0
      - PreserveHostHeader=
```

### **Bước 6: Cập nhật Database Migration (nếu cần)**
Nếu có thay đổi schema database, tạo migration script:

```sql
-- V1.2__Add_product_permissions.sql
-- Thêm permissions mới vào user hiện có (nếu cần)
UPDATE users SET permissions = CONCAT(permissions, ',product:read') 
WHERE roles LIKE '%ROLE_USER%' AND permissions IS NOT NULL;
```

## 🎯 Best Practices

### **1. Permission Granularity**
- **Quá chi tiết**: `product:read:own`, `product:read:all` ❌
- **Vừa phải**: `product:read`, `product:create` ✅
- **Quá thô**: `product:all` ❌

### **2. Security Annotations**
```java
// ✅ Tốt - specific permission
@PreAuthorize("hasAuthority('product:delete')")

// ❌ Tránh - quá general  
@PreAuthorize("hasRole('ADMIN')")

// ✅ Tốt - kết hợp điều kiện
@PreAuthorize("hasAuthority('product:update') and @productService.isOwner(#id, authentication.name)")
```

### **3. Role Design**
- **ADMIN**: Full access to everything
- **MANAGER**: Business operations + some admin functions
- **STAFF**: Day-to-day operations
- **USER**: Read-only access
- **Custom roles**: Specialized permissions

### **4. API Design**
```java
// ✅ RESTful + Permission mapping
GET    /api/products         → product:read
POST   /api/products         → product:create  
PUT    /api/products/{id}    → product:update
DELETE /api/products/{id}    → product:delete
POST   /api/products/{id}/approve → product:approve
```

### **5. Frontend Integration**
Sử dụng metadata endpoint để build UI động:

```javascript
// Get available permissions
const response = await api.get('/api/auth/system/metadata');
const { permissionsByCategory, currentUserAuthorities } = response.data;

// Check permission
const canCreateProduct = currentUserAuthorities.includes('product:create');

// Render UI based on permissions
{canCreateProduct && <CreateProductButton />}
```

## 🔧 Testing Checklist

- [ ] Permission constants added to `Permission.java`
- [ ] Role mappings updated in `AuthorityUtils.java` 
- [ ] Validation updated in `AuthService.java`
- [ ] Controller created with proper `@PreAuthorize`
- [ ] API Gateway routes configured
- [ ] Metadata endpoint returns new permissions
- [ ] JWT tokens include new authorities
- [ ] Frontend can detect and use new permissions

## 📋 Migration Checklist

Khi deploy lên production:

1. **Database**: Update existing users với permissions mới (nếu cần)
2. **Cache**: Clear Redis cache untuk JWT blacklist
3. **Documentation**: Update API documentation
4. **Frontend**: Deploy frontend code có support permissions mới  
5. **Testing**: Verify permissions hoạt động đúng

## 🎯 Common Patterns

### **Hierarchical Permissions**
```java
// Manager có thể approve orders
// Admin có thể approve + override
@PreAuthorize("hasAuthority('order:approve') or hasRole('ADMIN')")
```

### **Owner-based Permissions**
```java
@PreAuthorize("hasAuthority('order:update') and @orderService.isOwner(#id, authentication.name)")
```

### **Complex Business Logic**
```java
@PreAuthorize("@orderService.canApprove(#id, authentication)")
```

Hệ thống permission này được thiết kế để **mở rộng dễ dàng** và **bảo mật cao**! 🔐