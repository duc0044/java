package com.auth.controller;

import com.auth.entity.PermissionEntity;
import com.auth.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/permissions")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class PermissionController {

    private final PermissionRepository permissionRepository;

    @GetMapping
    @PreAuthorize("hasAuthority('role:manage')")
    public ResponseEntity<?> getAllPermissions(
            @RequestParam(required = false) String category,
            Pageable pageable
    ) {
        Page<PermissionEntity> permissions;
        
        if (category != null && !category.isEmpty()) {
            permissions = permissionRepository.findByCategory(category, pageable);
        } else {
            permissions = permissionRepository.findAll(pageable);
        }
        
        Map<String, Object> response = new HashMap<>();
        response.put("content", permissions.getContent());
        response.put("currentPage", permissions.getNumber());
        response.put("totalItems", permissions.getTotalElements());
        response.put("totalPages", permissions.getTotalPages());
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/all")
    @PreAuthorize("hasAuthority('role:manage')")
    public ResponseEntity<List<PermissionEntity>> getAllPermissionsWithoutPaging() {
        return ResponseEntity.ok(permissionRepository.findAll());
    }

    @GetMapping("/categories")
    @PreAuthorize("hasAuthority('role:manage')")
    public ResponseEntity<List<String>> getCategories() {
        return ResponseEntity.ok(permissionRepository.findDistinctCategories());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('role:manage')")
    public ResponseEntity<PermissionEntity> getPermissionById(@PathVariable Long id) {
        return permissionRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    @PreAuthorize("hasAuthority('role:manage')")
    public ResponseEntity<?> createPermission(@RequestBody PermissionEntity permission) {
        // Check if permission name already exists
        if (permissionRepository.findByName(permission.getName()).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Permission with name '" + permission.getName() + "' already exists"
            ));
        }
        
        PermissionEntity saved = permissionRepository.save(permission);
        return ResponseEntity.ok(saved);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('role:manage')")
    public ResponseEntity<?> updatePermission(
            @PathVariable Long id,
            @RequestBody PermissionEntity permissionDetails
    ) {
        return permissionRepository.findById(id)
                .map(permission -> {
                    // Check if new name conflicts with existing permission
                    if (!permission.getName().equals(permissionDetails.getName())) {
                        if (permissionRepository.findByName(permissionDetails.getName()).isPresent()) {
                            return ResponseEntity.badRequest().body(Map.of(
                                "error", "Permission with name '" + permissionDetails.getName() + "' already exists"
                            ));
                        }
                    }
                    
                    permission.setName(permissionDetails.getName());
                    permission.setDescription(permissionDetails.getDescription());
                    permission.setCategory(permissionDetails.getCategory());
                    
                    PermissionEntity updated = permissionRepository.save(permission);
                    return ResponseEntity.ok(updated);
                })
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('role:manage')")
    public ResponseEntity<?> deletePermission(@PathVariable Long id) {
        return permissionRepository.findById(id)
                .map(permission -> {
                    permissionRepository.delete(permission);
                    return ResponseEntity.ok(Map.of("message", "Permission deleted successfully"));
                })
                .orElse(ResponseEntity.notFound().build());
    }
}
