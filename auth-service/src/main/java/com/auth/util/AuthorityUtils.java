package com.auth.util;

import com.auth.entity.Permission;
import java.util.*;

public class AuthorityUtils {
    
    private static final Map<String, List<String>> ROLE_PERMISSIONS = new HashMap<>();

    static {
        ROLE_PERMISSIONS.put("ROLE_ADMIN", Arrays.asList(
            Permission.USER_READ,
            Permission.USER_CREATE,
            Permission.USER_UPDATE,
            Permission.USER_DELETE
        ));
        
        ROLE_PERMISSIONS.put("ROLE_STAFF", Arrays.asList(
            Permission.USER_READ,
            Permission.USER_CREATE,
            Permission.USER_UPDATE
        ));
        
        ROLE_PERMISSIONS.put("ROLE_USER", Collections.singletonList(
            Permission.USER_READ
        ));
    }

    public static Collection<String> getAuthorities(String rolesString, String permissionsString) {
        Set<String> authorities = new HashSet<>();
        
        // Add role-based permissions
        if (rolesString != null && !rolesString.isEmpty()) {
            String[] roles = rolesString.split(",");
            for (String role : roles) {
                authorities.add(role.trim());
                List<String> permissions = ROLE_PERMISSIONS.get(role.trim());
                if (permissions != null) {
                    authorities.addAll(permissions);
                }
            }
        }
        
        // Add direct permissions
        if (permissionsString != null && !permissionsString.isEmpty()) {
            String[] permissions = permissionsString.split(",");
            for (String permission : permissions) {
                authorities.add(permission.trim());
            }
        }
        
        return authorities;
    }
    
    // Default method for backward compatibility if needed, though we should update callers
    public static Collection<String> getAuthorities(String rolesString) {
        return getAuthorities(rolesString, null);
    }
}
