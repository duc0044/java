package com.auth.controller;

import com.auth.dto.*;
import com.auth.repository.UserRepository;
import com.auth.service.AuthService;
import com.auth.service.RolePermissionService;
import com.auth.entity.User;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    
    private final AuthService authService;
    private final UserRepository userRepository;
    private final RolePermissionService rolePermissionService;
    
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        AuthResponse response = authService.register(request);
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        AuthResponse response = authService.refreshToken(request);
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader(value = "Authorization", required = false) String token) {
        authService.logout(token);
        return ResponseEntity.ok("Đăng xuất thành công");
    }

    @GetMapping("/me")
    public ResponseEntity<UserResponse> getCurrentUser(@AuthenticationPrincipal String email) {
        var user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User không tồn tại"));
        
        return ResponseEntity.ok(UserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .username(user.getUsername())
                .roles(user.getRoles())
                .permissions(user.getPermissions())
                .build());
    }

    @GetMapping("/dashboard/summary")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('user:read')")
    public ResponseEntity<DashboardDTO> getDashboardSummary() {
        DashboardDTO summary = DashboardDTO.builder()
                .totalUsers(userRepository.count())
                .activeSessions(5)
                .systemHealth("Excellent")
                .recentActivity(List.of(
                    "User 'admin' logged in",
                    "Database backup completed",
                    "New user registered"
                ))
                .build();
        
        return ResponseEntity.ok(summary);
    }
    
    @GetMapping("/system/metadata")
    @PreAuthorize("hasAuthority('user:read')")
    public ResponseEntity<Map<String, Object>> getSystemMetadata() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("availableRoles", Arrays.asList("ROLE_USER", "ROLE_STAFF", "ROLE_ADMIN", "ROLE_MANAGER"));
        metadata.put("permissionsByCategory", rolePermissionService.getPermissionsByCategory());
        
        // Current user info
        String currentEmail = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication().getName();
        var currentUser = userRepository.findByEmail(currentEmail);
        if (currentUser.isPresent()) {
            User user = currentUser.get();
            Set<String> authorities = rolePermissionService.getUserAuthorities(user);
            metadata.put("currentUserAuthorities", authorities);
            
            // Add current user role/permission info for frontend convenience
            String rolesString = user.getRoles().stream()
                .map(com.auth.entity.Role::getName)
                .collect(java.util.stream.Collectors.joining(","));
            String permissionsString = user.getPermissions().stream()
                .map(com.auth.entity.PermissionEntity::getName)
                .collect(java.util.stream.Collectors.joining(","));
                
            metadata.put("currentUserRoles", rolesString);
            metadata.put("currentUserPermissions", permissionsString.isEmpty() ? null : permissionsString);
        }
        
        return ResponseEntity.ok(metadata);
    }
}
