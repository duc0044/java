package com.auth.util;

import com.auth.entity.Permission;
import java.util.*;

public class AuthorityUtils {
    
    private static final Map<String, List<String>> ROLE_PERMISSIONS = new HashMap<>();

    static {
        // ADMIN: Full access to everything
        ROLE_PERMISSIONS.put("ROLE_ADMIN", Arrays.asList(
            // User Management
            Permission.USER_READ, Permission.USER_CREATE, Permission.USER_UPDATE, Permission.USER_DELETE,
            // Report Management
            Permission.REPORT_READ, Permission.REPORT_CREATE, Permission.REPORT_UPDATE, 
            Permission.REPORT_DELETE, Permission.REPORT_EXPORT,
            // Order Management
            Permission.ORDER_READ, Permission.ORDER_CREATE, Permission.ORDER_UPDATE,
            Permission.ORDER_DELETE, Permission.ORDER_APPROVE,
            // System Administration
            Permission.SYSTEM_CONFIG, Permission.SYSTEM_BACKUP, Permission.AUDIT_READ
        ));
        
        // STAFF: Business operations permissions
        ROLE_PERMISSIONS.put("ROLE_STAFF", Arrays.asList(
            // User Management (limited)
            Permission.USER_READ, Permission.USER_CREATE, Permission.USER_UPDATE,
            // Report Management (full except delete)
            Permission.REPORT_READ, Permission.REPORT_CREATE, Permission.REPORT_UPDATE, Permission.REPORT_EXPORT,
            // Order Management (full business operations)
            Permission.ORDER_READ, Permission.ORDER_CREATE, Permission.ORDER_UPDATE, Permission.ORDER_APPROVE
        ));
        
        // USER: Read-only access
        ROLE_PERMISSIONS.put("ROLE_USER", Arrays.asList(
            Permission.USER_READ,
            Permission.REPORT_READ,
            Permission.ORDER_READ
        ));
        
        // Optional: Add specialized roles
        ROLE_PERMISSIONS.put("ROLE_MANAGER", Arrays.asList(
            // User Management (limited)
            Permission.USER_READ, Permission.USER_UPDATE,
            // Report Management (full)
            Permission.REPORT_READ, Permission.REPORT_CREATE, Permission.REPORT_UPDATE, 
            Permission.REPORT_DELETE, Permission.REPORT_EXPORT,
            // Order Management (approve focus)
            Permission.ORDER_READ, Permission.ORDER_UPDATE, Permission.ORDER_APPROVE,
            // Some system access
            Permission.AUDIT_READ
        ));
    }

    public static Collection<String> getAuthorities(String rolesString, String permissionsString) {
        Set<String> authorities = new HashSet<>();
        
        // Add role-based permissions
        if (rolesString != null && !rolesString.trim().isEmpty()) {
            String[] roles = rolesString.split(",");
            for (String role : roles) {
                String trimmedRole = role.trim();
                authorities.add(trimmedRole);
                List<String> permissions = ROLE_PERMISSIONS.get(trimmedRole);
                if (permissions != null) {
                    authorities.addAll(permissions);
                }
            }
        }
        
        // Add direct permissions
        if (permissionsString != null && !permissionsString.trim().isEmpty()) {
            String[] permissions = permissionsString.split(",");
            for (String permission : permissions) {
                String trimmedPermission = permission.trim();
                if (!trimmedPermission.isEmpty()) {
                    authorities.add(trimmedPermission);
                }
            }
        }
        
        return authorities;
    }
    
    // Default method for backward compatibility
    public static Collection<String> getAuthorities(String rolesString) {
        return getAuthorities(rolesString, null);
    }
    
    // Utility method to check if user has specific permission
    public static boolean hasPermission(String userRoles, String userPermissions, String requiredPermission) {
        Collection<String> authorities = getAuthorities(userRoles, userPermissions);
        return authorities.contains(requiredPermission);
    }
    
    // Get available permission constants
    public static List<String> getAllPermissions() {
        return Arrays.asList(
            // User Management
            Permission.USER_READ, Permission.USER_CREATE, Permission.USER_UPDATE, Permission.USER_DELETE,
            // Report Management
            Permission.REPORT_READ, Permission.REPORT_CREATE, Permission.REPORT_UPDATE, 
            Permission.REPORT_DELETE, Permission.REPORT_EXPORT,
            // Order Management
            Permission.ORDER_READ, Permission.ORDER_CREATE, Permission.ORDER_UPDATE,
            Permission.ORDER_DELETE, Permission.ORDER_APPROVE,
            // System Administration
            Permission.SYSTEM_CONFIG, Permission.SYSTEM_BACKUP, Permission.AUDIT_READ
        );
    }
    
    // Get permissions by category (helpful for frontend organization)
    public static Map<String, List<String>> getPermissionsByCategory() {
        Map<String, List<String>> categories = new HashMap<>();
        
        categories.put("User Management", Arrays.asList(
            Permission.USER_READ, Permission.USER_CREATE, Permission.USER_UPDATE, Permission.USER_DELETE
        ));
        
        categories.put("Report Management", Arrays.asList(
            Permission.REPORT_READ, Permission.REPORT_CREATE, Permission.REPORT_UPDATE, 
            Permission.REPORT_DELETE, Permission.REPORT_EXPORT
        ));
        
        categories.put("Order Management", Arrays.asList(
            Permission.ORDER_READ, Permission.ORDER_CREATE, Permission.ORDER_UPDATE,
            Permission.ORDER_DELETE, Permission.ORDER_APPROVE
        ));
        
        categories.put("System Administration", Arrays.asList(
            Permission.SYSTEM_CONFIG, Permission.SYSTEM_BACKUP, Permission.AUDIT_READ
        ));
        
        return categories;
    }
}
