-- Sample Data for Authentication System

-- Insert sample users with hashed passwords (using bcrypt hashes)
INSERT INTO users (email, username, password, provider, roles, permissions, created_at, updated_at) VALUES
-- Admin user: admin@admin.com / password123
('admin@admin.com', 'admin', '$2a$10$slYQmyNdGzin7olVB4itCOYccZmrG/Rg25lF0XNjmN.G67/vZfIya', 'LOCAL', 'ROLE_ADMIN', 'user:read,user:create,user:update,user:delete', NOW(), NOW()),

-- Regular users
('john@example.com', 'john_doe', '$2a$10$slYQmyNdGzin7olVB4itCOYccZmrG/Rg25lF0XNjmN.G67/vZfIya', 'LOCAL', 'ROLE_USER', 'user:read', NOW(), NOW()),
('jane@example.com', 'jane_smith', '$2a$10$slYQmyNdGzin7olVB4itCOYccZmrG/Rg25lF0XNjmN.G67/vZfIya', 'LOCAL', 'ROLE_USER', 'user:read,user:create', NOW(), NOW()),
('bob@example.com', 'bob_wilson', '$2a$10$slYQmyNdGzin7olVB4itCOYccZmrG/Rg25lF0XNjmN.G67/vZfIya', 'LOCAL', 'ROLE_USER', 'user:read', NOW(), NOW()),
('alice@example.com', 'alice_johnson', '$2a$10$slYQmyNdGzin7olVB4itCOYccZmrG/Rg25lF0XNjmN.G67/vZfIya', 'LOCAL', 'ROLE_USER', 'user:read,user:update', NOW(), NOW()),

-- Admin user 2
('manager@example.com', 'manager', '$2a$10$slYQmyNdGzin7olVB4itCOYccZmrG/Rg25lF0XNjmN.G67/vZfIya', 'LOCAL', 'ROLE_ADMIN', 'user:read,user:create,user:update,user:delete', NOW(), NOW()),

-- Google OAuth user
('googleuser@gmail.com', 'google_user', NULL, 'GOOGLE', 'ROLE_USER', 'user:read', NOW(), NOW());

-- Display inserted data
SELECT 'Sample data inserted successfully!' as message;
SELECT COUNT(*) as total_users FROM users;
SELECT * FROM users;
