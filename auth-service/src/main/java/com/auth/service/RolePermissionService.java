package com.auth.service;

import com.auth.entity.*;
import com.auth.repository.PermissionRepository;
import com.auth.repository.RoleRepository;
import com.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class RolePermissionService implements ApplicationRunner {
    
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final UserRepository userRepository;
    
    @Override
    @Transactional
    public void run(ApplicationArguments args) throws Exception {
        log.info("Initializing roles and permissions...");
        initializePermissions();
        initializeRoles();
        migrateLegacyData();
        log.info("Roles and permissions initialization completed");
    }
    
    private void initializePermissions() {
        // User Management Permissions
        createPermissionIfNotExists("user:read", "View users", "User Management");
        createPermissionIfNotExists("user:create", "Create new users", "User Management");
        createPermissionIfNotExists("user:update", "Update user information", "User Management");
        createPermissionIfNotExists("user:delete", "Delete users", "User Management");
        
        // Report Management Permissions
        createPermissionIfNotExists("report:read", "View reports", "Report Management");
        createPermissionIfNotExists("report:create", "Create new reports", "Report Management");
        createPermissionIfNotExists("report:update", "Update reports", "Report Management");
        createPermissionIfNotExists("report:delete", "Delete reports", "Report Management");
        createPermissionIfNotExists("report:export", "Export reports", "Report Management");
        
        // Order Management Permissions
        createPermissionIfNotExists("order:read", "View orders", "Order Management");
        createPermissionIfNotExists("order:create", "Create new orders", "Order Management");
        createPermissionIfNotExists("order:update", "Update orders", "Order Management");
        createPermissionIfNotExists("order:delete", "Delete orders", "Order Management");
        createPermissionIfNotExists("order:approve", "Approve orders", "Order Management");
        
        // System Administration Permissions
        createPermissionIfNotExists("system:config", "Configure system settings", "System Administration");
        createPermissionIfNotExists("system:backup", "Backup system data", "System Administration");
        createPermissionIfNotExists("audit:read", "View audit logs", "System Administration");
    }
    
    private void initializeRoles() {
        // Create ROLE_USER
        Role userRole = createRoleIfNotExists("ROLE_USER", "Standard user role");
        assignPermissionsToRole(userRole, Set.of("user:read", "report:read", "order:read"));
        
        // Create ROLE_STAFF  
        Role staffRole = createRoleIfNotExists("ROLE_STAFF", "Staff member role");
        assignPermissionsToRole(staffRole, Set.of(
            "user:read", "user:create", "user:update",
            "report:read", "report:create", "report:update", "report:export",
            "order:read", "order:create", "order:update", "order:approve"
        ));
        
        // Create ROLE_MANAGER
        Role managerRole = createRoleIfNotExists("ROLE_MANAGER", "Manager role");
        assignPermissionsToRole(managerRole, Set.of(
            "user:read", "user:update",
            "report:read", "report:create", "report:update", "report:delete", "report:export",
            "order:read", "order:update", "order:approve",
            "audit:read"
        ));
        
        // Create ROLE_ADMIN
        Role adminRole = createRoleIfNotExists("ROLE_ADMIN", "Administrator role");
        Set<String> allPermissions = permissionRepository.findAll()
            .stream()
            .map(PermissionEntity::getName)
            .collect(Collectors.toSet());
        assignPermissionsToRole(adminRole, allPermissions);
    }
    
    @Transactional
    public void migrateLegacyData() {
        log.info("Migrating legacy role/permission data...");
        
        List<User> usersToMigrate = userRepository.findAll().stream()
            .filter(user -> user.getLegacyRoles() != null || user.getLegacyPermissions() != null)
            .toList();
            
        for (User user : usersToMigrate) {
            try {
                migrateSingleUser(user);
            } catch (Exception e) {
                log.error("Failed to migrate user {}: {}", user.getEmail(), e.getMessage());
            }
        }
        
        log.info("Migration completed for {} users", usersToMigrate.size());
    }
    
    private void migrateSingleUser(User user) {
        // Migrate roles
        if (user.getLegacyRoles() != null && !user.getLegacyRoles().trim().isEmpty()) {
            String[] roleNames = user.getLegacyRoles().split(",");
            Set<Role> roles = new HashSet<>();
            
            for (String roleName : roleNames) {
                String trimmedRole = roleName.trim();
                roleRepository.findByName(trimmedRole)
                    .ifPresent(roles::add);
            }
            
            user.setRoles(roles);
        }
        
        // Migrate direct permissions
        if (user.getLegacyPermissions() != null && !user.getLegacyPermissions().trim().isEmpty()) {
            String[] permissionNames = user.getLegacyPermissions().split(",");
            Set<PermissionEntity> permissions = new HashSet<>();
            
            for (String permissionName : permissionNames) {
                String trimmedPermission = permissionName.trim();
                if (!trimmedPermission.isEmpty()) {
                    permissionRepository.findByName(trimmedPermission)
                        .ifPresent(permissions::add);
                }
            }
            
            user.setPermissions(permissions);
        }
        
        userRepository.save(user);
        log.debug("Migrated user: {}", user.getEmail());
    }
    
    private void createPermissionIfNotExists(String name, String description, String category) {
        if (!permissionRepository.existsByName(name)) {
            PermissionEntity permission = PermissionEntity.builder()
                .name(name)
                .description(description)
                .category(category)
                .build();
            permissionRepository.save(permission);
        }
    }
    
    private Role createRoleIfNotExists(String name, String description) {
        return roleRepository.findByName(name)
            .orElseGet(() -> {
                Role role = Role.builder()
                    .name(name)
                    .description(description)
                    .permissions(new HashSet<>())
                    .build();
                return roleRepository.save(role);
            });
    }
    
    private void assignPermissionsToRole(Role role, Set<String> permissionNames) {
        Set<PermissionEntity> permissions = permissionRepository.findByNameIn(permissionNames);
        role.setPermissions(permissions);
        roleRepository.save(role);
    }
    
    // Utility methods for service layer
    public Set<String> getUserAuthorities(User user) {
        Set<String> authorities = new HashSet<>();
        
        // Add roles
        user.getRoles().forEach(role -> {
            authorities.add(role.getName());
            // Add role-based permissions
            role.getPermissions().forEach(permission -> 
                authorities.add(permission.getName()));
        });
        
        // Add direct permissions
        user.getPermissions().forEach(permission -> 
            authorities.add(permission.getName()));
            
        return authorities;
    }
    
    public Map<String, List<String>> getPermissionsByCategory() {
        return permissionRepository.findAll()
            .stream()
            .collect(Collectors.groupingBy(
                PermissionEntity::getCategory,
                Collectors.mapping(PermissionEntity::getName, Collectors.toList())
            ));
    }
}