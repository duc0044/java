-- Migration script to create proper role/permission tables
-- Run this after the application starts and entities are created

-- 1. Create roles table (if not exist by JPA)
CREATE TABLE IF NOT EXISTS roles (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description VARCHAR(255)
);

-- 2. Create permissions table (if not exist by JPA)  
CREATE TABLE IF NOT EXISTS permissions (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description VARCHAR(255),
    category VARCHAR(50)
);

-- 3. Create user_roles junction table (if not exist by JPA)
CREATE TABLE IF NOT EXISTS user_roles (
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

-- 4. Create user_permissions junction table (if not exist by JPA)
CREATE TABLE IF NOT EXISTS user_permissions (
    user_id BIGINT NOT NULL,
    permission_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, permission_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

-- 5. Create role_permissions junction table (if not exist by JPA)
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id BIGINT NOT NULL,
    permission_id BIGINT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

-- 6. Add legacy columns to users table for migration support
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS legacy_roles VARCHAR(50),
ADD COLUMN IF NOT EXISTS legacy_permissions TEXT;

-- 7. Copy existing data to legacy columns (backup)
UPDATE users 
SET legacy_roles = roles, 
    legacy_permissions = permissions
WHERE legacy_roles IS NULL;

-- 8. Make original columns nullable for migration
ALTER TABLE users ALTER COLUMN roles DROP NOT NULL;

-- 9. Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_permissions_user_id ON user_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_permissions_permission_id ON user_permissions(permission_id);  
CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);
CREATE INDEX IF NOT EXISTS idx_permissions_category ON permissions(category);

-- 10. Insert default data (will be handled by RolePermissionService)
-- This is just documentation of what the service will create:

/*
-- Default Permissions
INSERT INTO permissions (name, description, category) VALUES
-- User Management
('user:read', 'View users', 'User Management'),
('user:create', 'Create new users', 'User Management'), 
('user:update', 'Update user information', 'User Management'),
('user:delete', 'Delete users', 'User Management'),

-- Report Management  
('report:read', 'View reports', 'Report Management'),
('report:create', 'Create new reports', 'Report Management'),
('report:update', 'Update reports', 'Report Management'),
('report:delete', 'Delete reports', 'Report Management'),
('report:export', 'Export reports', 'Report Management'),

-- Order Management
('order:read', 'View orders', 'Order Management'),
('order:create', 'Create new orders', 'Order Management'), 
('order:update', 'Update orders', 'Order Management'),
('order:delete', 'Delete orders', 'Order Management'),
('order:approve', 'Approve orders', 'Order Management'),

-- System Administration
('system:config', 'Configure system settings', 'System Administration'),
('system:backup', 'Backup system data', 'System Administration'),
('audit:read', 'View audit logs', 'System Administration')
ON CONFLICT (name) DO NOTHING;

-- Default Roles
INSERT INTO roles (name, description) VALUES
('ROLE_USER', 'Standard user role'),
('ROLE_STAFF', 'Staff member role'),
('ROLE_MANAGER', 'Manager role'),
('ROLE_ADMIN', 'Administrator role')
ON CONFLICT (name) DO NOTHING;
*/