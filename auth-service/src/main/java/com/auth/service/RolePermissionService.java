package com.auth.service;

import com.auth.entity.PermissionEntity;
import com.auth.entity.Role;
import com.auth.entity.User;
import com.auth.repository.PermissionRepository;
import com.auth.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class RolePermissionService implements ApplicationRunner {
    
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    
    @Override
    @Transactional
    public void run(ApplicationArguments args) throws Exception {
        log.info("Initializing roles and permissions...");
        initializePermissions();
        initializeRoles();
        log.info("Roles and permissions initialized successfully");
    }
    
    private void initializePermissions() {
        // User Management Permissions
        createPermissionIfNotExists("user:read", "View users", "User Management");
        createPermissionIfNotExists("user:create", "Create users", "User Management");
        createPermissionIfNotExists("user:update", "Update users", "User Management");
        createPermissionIfNotExists("user:delete", "Delete users", "User Management");
        
        // Report Management Permissions
        createPermissionIfNotExists("report:read", "View reports", "Report Management");
        createPermissionIfNotExists("report:create", "Create reports", "Report Management");
        createPermissionIfNotExists("report:update", "Update reports", "Report Management");
        createPermissionIfNotExists("report:delete", "Delete reports", "Report Management");
        createPermissionIfNotExists("report:export", "Export reports", "Report Management");
        
        // Order Management Permissions
        createPermissionIfNotExists("order:read", "View orders", "Order Management");
        createPermissionIfNotExists("order:create", "Create orders", "Order Management");
        createPermissionIfNotExists("order:update", "Update orders", "Order Management");
        createPermissionIfNotExists("order:delete", "Delete orders", "Order Management");
        createPermissionIfNotExists("order:approve", "Approve orders", "Order Management");
        
        // System Administration Permissions
        createPermissionIfNotExists("system:config", "Configure system", "System Administration");
        createPermissionIfNotExists("system:backup", "Backup system", "System Administration");
        createPermissionIfNotExists("audit:read", "View audit logs", "System Administration");
    }
    
    private void createPermissionIfNotExists(String name, String description, String category) {
        if (!permissionRepository.existsByName(name)) {
            PermissionEntity permission = PermissionEntity.builder()
                    .name(name)
                    .description(description)
                    .category(category)
                    .build();
            permissionRepository.save(permission);
            log.info("Created permission: {}", name);
        }
    }
    
    private void initializeRoles() {
        // ROLE_USER - basic permissions
        createRoleIfNotExists("ROLE_USER", "Standard User", 
            Set.of("user:read"));
        
        // ROLE_STAFF - can manage reports and orders
        createRoleIfNotExists("ROLE_STAFF", "Staff Member",
            Set.of("user:read", "report:read", "report:create", "order:read", "order:create"));
        
        // ROLE_MANAGER - can manage users, reports, and orders
        createRoleIfNotExists("ROLE_MANAGER", "Manager",
            Set.of("user:read", "user:create", "user:update",
                   "report:read", "report:create", "report:update", "report:export",
                   "order:read", "order:create", "order:update", "order:approve"));
        
        // ROLE_ADMIN - full permissions
        createRoleIfNotExists("ROLE_ADMIN", "Administrator",
            Set.of("user:read", "user:create", "user:update", "user:delete",
                   "report:read", "report:create", "report:update", "report:delete", "report:export",
                   "order:read", "order:create", "order:update", "order:delete", "order:approve",
                   "system:config", "system:backup", "audit:read"));
    }
    
    private void createRoleIfNotExists(String name, String description, Set<String> permissionNames) {
        if (!roleRepository.existsByName(name)) {
            // Add permissions to role
            Set<PermissionEntity> permissions = permissionRepository.findByNameIn(permissionNames);
            
            Role role = Role.builder()
                    .name(name)
                    .description(description)
                    .permissions(permissions)
                    .build();
            
            roleRepository.save(role);
            log.info("Created role: {} with {} permissions", name, permissions.size());
        }
    }
    
    public Set<String> getUserAuthorities(User user) {
        Set<String> authorities = new HashSet<>();
        
        // Add roles
        if (user.getRoles() != null) {
            user.getRoles().forEach(role -> {
                authorities.add(role.getName());
                // Add permissions from role
                if (role.getPermissions() != null) {
                    role.getPermissions().forEach(perm -> authorities.add(perm.getName()));
                }
            });
        }
        
        // Add direct user permissions
        if (user.getPermissions() != null) {
            user.getPermissions().forEach(perm -> authorities.add(perm.getName()));
        }
        
        return authorities;
    }
    
    public Map<String, List<String>> getPermissionsByCategory() {
        Map<String, List<String>> permissionsByCategory = new HashMap<>();
        
        // User Management Permissions
        permissionsByCategory.put("User Management", Arrays.asList(
            com.auth.entity.Permission.USER_READ,
            com.auth.entity.Permission.USER_CREATE,
            com.auth.entity.Permission.USER_UPDATE,
            com.auth.entity.Permission.USER_DELETE
        ));
        
        // Report Management Permissions
        permissionsByCategory.put("Report Management", Arrays.asList(
            com.auth.entity.Permission.REPORT_READ,
            com.auth.entity.Permission.REPORT_CREATE,
            com.auth.entity.Permission.REPORT_UPDATE,
            com.auth.entity.Permission.REPORT_DELETE,
            com.auth.entity.Permission.REPORT_EXPORT
        ));
        
        // Order Management Permissions
        permissionsByCategory.put("Order Management", Arrays.asList(
            com.auth.entity.Permission.ORDER_READ,
            com.auth.entity.Permission.ORDER_CREATE,
            com.auth.entity.Permission.ORDER_UPDATE,
            com.auth.entity.Permission.ORDER_DELETE,
            com.auth.entity.Permission.ORDER_APPROVE
        ));
        
        // System Administration Permissions
        permissionsByCategory.put("System Administration", Arrays.asList(
            com.auth.entity.Permission.SYSTEM_CONFIG,
            com.auth.entity.Permission.SYSTEM_BACKUP,
            com.auth.entity.Permission.AUDIT_READ
        ));
        
        return permissionsByCategory;
    }
}
