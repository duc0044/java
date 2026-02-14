package com.auth.controller;

import com.auth.entity.PermissionEntity;
import com.auth.entity.Role;
import com.auth.repository.PermissionRepository;
import com.auth.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/roles")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class RoleController {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;

    @GetMapping
    @PreAuthorize("hasAuthority('role:manage')")
    public ResponseEntity<?> getAllRoles(Pageable pageable) {
        Page<Role> roles = roleRepository.findAll(pageable);
        
        Map<String, Object> response = new HashMap<>();
        response.put("content", roles.getContent());
        response.put("currentPage", roles.getNumber());
        response.put("totalItems", roles.getTotalElements());
        response.put("totalPages", roles.getTotalPages());
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/all")
    @PreAuthorize("hasAuthority('role:manage')")
    public ResponseEntity<List<Role>> getAllRolesWithoutPaging() {
        return ResponseEntity.ok(roleRepository.findAll());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('role:manage')")
    public ResponseEntity<?> getRoleById(@PathVariable Long id) {
        return roleRepository.findById(id)
                .map(role -> {
                    Map<String, Object> response = new HashMap<>();
                    response.put("id", role.getId());
                    response.put("name", role.getName());
                    response.put("description", role.getDescription());
                    response.put("permissions", role.getPermissions().stream()
                            .map(PermissionEntity::getName)
                            .collect(Collectors.toSet()));
                    return ResponseEntity.ok(response);
                })
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    @PreAuthorize("hasAuthority('role:manage')")
    public ResponseEntity<?> createRole(@RequestBody Map<String, Object> roleData) {
        String name = (String) roleData.get("name");
        String description = (String) roleData.get("description");
        @SuppressWarnings("unchecked")
        Set<String> permissionNames = roleData.get("permissions") != null 
            ? new HashSet<>((List<String>) roleData.get("permissions"))
            : new HashSet<>();

        // Check if role name already exists
        if (roleRepository.findByName(name).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Role with name '" + name + "' already exists"
            ));
        }

        // Find permissions
        Set<PermissionEntity> permissions = permissionNames.isEmpty() 
            ? new HashSet<>() 
            : permissionRepository.findByNameIn(permissionNames);

        Role role = Role.builder()
                .name(name)
                .description(description)
                .permissions(permissions)
                .build();

        Role saved = roleRepository.save(role);
        
        Map<String, Object> response = new HashMap<>();
        response.put("id", saved.getId());
        response.put("name", saved.getName());
        response.put("description", saved.getDescription());
        response.put("permissions", saved.getPermissions().stream()
                .map(PermissionEntity::getName)
                .collect(Collectors.toSet()));
        
        return ResponseEntity.ok(response);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('role:manage')")
    public ResponseEntity<?> updateRole(
            @PathVariable Long id,
            @RequestBody Map<String, Object> roleData
    ) {
        return roleRepository.findById(id)
                .map(role -> {
                    String name = (String) roleData.get("name");
                    String description = (String) roleData.get("description");
                    @SuppressWarnings("unchecked")
                    Set<String> permissionNames = roleData.get("permissions") != null 
                        ? new HashSet<>((List<String>) roleData.get("permissions"))
                        : new HashSet<>();

                    // Check if new name conflicts with existing role
                    if (!role.getName().equals(name)) {
                        if (roleRepository.findByName(name).isPresent()) {
                            return ResponseEntity.badRequest().body(Map.of(
                                "error", "Role with name '" + name + "' already exists"
                            ));
                        }
                    }

                    // Find permissions
                    Set<PermissionEntity> permissions = permissionNames.isEmpty() 
                        ? new HashSet<>() 
                        : permissionRepository.findByNameIn(permissionNames);

                    role.setName(name);
                    role.setDescription(description);
                    role.setPermissions(permissions);

                    Role updated = roleRepository.save(role);
                    
                    Map<String, Object> response = new HashMap<>();
                    response.put("id", updated.getId());
                    response.put("name", updated.getName());
                    response.put("description", updated.getDescription());
                    response.put("permissions", updated.getPermissions().stream()
                            .map(PermissionEntity::getName)
                            .collect(Collectors.toSet()));
                    
                    return ResponseEntity.ok(response);
                })
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('role:manage')")
    public ResponseEntity<?> deleteRole(@PathVariable Long id) {
        return roleRepository.findById(id)
                .map(role -> {
                    // Prevent deletion of system roles
                    if (role.getName().equals("ROLE_ADMIN") || 
                        role.getName().equals("ROLE_USER")) {
                        return ResponseEntity.badRequest().body(Map.of(
                            "error", "Cannot delete system role: " + role.getName()
                        ));
                    }
                    
                    roleRepository.delete(role);
                    return ResponseEntity.ok(Map.of("message", "Role deleted successfully"));
                })
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/{roleId}/permissions")
    @PreAuthorize("hasAuthority('role:manage')")
    public ResponseEntity<?> assignPermissionsToRole(
            @PathVariable Long roleId,
            @RequestBody Map<String, Set<String>> request
    ) {
        Set<String> permissionNames = request.get("permissions");
        
        return roleRepository.findById(roleId)
                .map(role -> {
                    Set<PermissionEntity> permissions = permissionRepository.findByNameIn(permissionNames);
                    role.setPermissions(permissions);
                    roleRepository.save(role);
                    
                    return ResponseEntity.ok(Map.of(
                        "message", "Permissions assigned successfully",
                        "role", role.getName(),
                        "permissions", permissions.stream()
                                .map(PermissionEntity::getName)
                                .collect(Collectors.toSet())
                    ));
                })
                .orElse(ResponseEntity.notFound().build());
    }
}
