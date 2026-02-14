package com.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@lombok.RequiredArgsConstructor
public class UserManagementController {

    private final com.auth.service.AuthService authService;
    private final com.auth.repository.UserRepository userRepository;

    @GetMapping
    @PreAuthorize("hasAuthority('user:read')")
    public ResponseEntity<com.auth.dto.PageResponse<com.auth.dto.UserResponse>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(required = false) String search,
            @RequestParam(required = false) String role) {
        org.springframework.data.domain.Pageable pageable = org.springframework.data.domain.PageRequest.of(page, size, org.springframework.data.domain.Sort.by("createdAt").descending());
        return ResponseEntity.ok(authService.listUsers(search, role, pageable));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('user:read')")
    public ResponseEntity<com.auth.dto.UserResponse> getUserById(@PathVariable Long id) {
        com.auth.entity.User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User không tồn tại"));
        
        java.util.Set<String> roleNames = user.getRoles() != null 
                ? user.getRoles().stream().map(com.auth.entity.Role::getName).collect(java.util.stream.Collectors.toSet())
                : new java.util.HashSet<>();
        
        java.util.Set<String> allPermissions = new java.util.HashSet<>();
        if (user.getRoles() != null) {
            user.getRoles().forEach(role -> {
                if (role.getPermissions() != null) {
                    role.getPermissions().forEach(perm -> allPermissions.add(perm.getName()));
                }
            });
        }
        if (user.getPermissions() != null) {
            user.getPermissions().forEach(perm -> allPermissions.add(perm.getName()));
        }
        
        com.auth.dto.UserResponse response = com.auth.dto.UserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .username(user.getUsername())
                .roles(roleNames)
                .permissions(allPermissions)
                .build();
                
        return ResponseEntity.ok(response);
    }

    @PostMapping
    @PreAuthorize("hasAuthority('user:create')")
    public ResponseEntity<com.auth.dto.UserResponse> createUser(@RequestBody com.auth.dto.RegisterRequest request) {
        return ResponseEntity.ok(authService.createUser(request));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('user:update')")
    public ResponseEntity<com.auth.dto.UserResponse> updateUser(@PathVariable Long id, @RequestBody com.auth.dto.UpdateUserRequest request) {
        return ResponseEntity.ok(authService.updateUser(id, request));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('user:delete')")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        authService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}
