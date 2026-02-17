package com.auth.controller;

import com.auth.client.FileServiceClient;
import com.auth.dto.AvatarUploadResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/users")
@lombok.RequiredArgsConstructor
public class UserManagementController {

    private final com.auth.service.AuthService authService;
    private final com.auth.repository.UserRepository userRepository;
    private final FileServiceClient fileServiceClient;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('user:read')")
    public ResponseEntity<com.auth.dto.PageResponse<com.auth.dto.UserResponse>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(required = false) String search,
            @RequestParam(required = false) String role) {
        org.springframework.data.domain.Pageable pageable = org.springframework.data.domain.PageRequest.of(page, size, org.springframework.data.domain.Sort.by("createdAt").descending());
        return ResponseEntity.ok(authService.listUsers(search, role, pageable));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('user:read')")
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
                .avatarUrl(user.getAvatarUrl())
                .roles(roleNames)
                .permissions(allPermissions)
                .build();
                
        return ResponseEntity.ok(response);
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('user:create')")
    public ResponseEntity<com.auth.dto.UserResponse> createUser(@RequestBody com.auth.dto.RegisterRequest request) {
        return ResponseEntity.ok(authService.createUser(request));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('user:update')")
    public ResponseEntity<com.auth.dto.UserResponse> updateUser(@PathVariable Long id, @RequestBody com.auth.dto.UpdateUserRequest request) {
        return ResponseEntity.ok(authService.updateUser(id, request));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('user:delete')")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        authService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    /**
     * Upload avatar for user
     */
    @PostMapping("/{id}/avatar")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<AvatarUploadResponse> uploadAvatar(
            @PathVariable Long id,
            @RequestParam("file") MultipartFile file,
            HttpServletRequest request) {
        
        try {
            // Get current user
            String currentEmail = org.springframework.security.core.context.SecurityContextHolder
                    .getContext().getAuthentication().getName();
            com.auth.entity.User currentUser = userRepository.findByEmail(currentEmail)
                    .orElseThrow(() -> new RuntimeException("User không tồn tại"));
            
            // Check if user can update this avatar (own avatar or admin)
            boolean isAdmin = currentUser.getRoles().stream()
                    .anyMatch(role -> "ROLE_ADMIN".equals(role.getName()));
            
            if (!currentUser.getId().equals(id) && !isAdmin) {
                throw new RuntimeException("Bạn không có quyền upload avatar cho user này");
            }
            
            // Get user to update
            com.auth.entity.User user = userRepository.findById(id)
                    .orElseThrow(() -> new RuntimeException("User không tồn tại"));
            
            // Extract token from request
            String authHeader = request.getHeader("Authorization");
            String token = authHeader != null && authHeader.startsWith("Bearer ") 
                    ? authHeader.substring(7) : null;
            
            if (token == null) {
                throw new RuntimeException("Missing authentication token");
            }
            
            // Delete old avatar if exists
            if (user.getAvatarUrl() != null && !user.getAvatarUrl().isEmpty()) {
                try {
                    fileServiceClient.deleteFile(user.getAvatarUrl(), token);
                } catch (Exception e) {
                    // Log error but continue with upload
                    System.err.println("Failed to delete old avatar: " + e.getMessage());
                }
            }
            
            // Upload new avatar to file-service with user-specific folder
            String folder = "avatars/user-" + id;
            String fileName = fileServiceClient.uploadFile(file, folder, token);
            
            // Update user avatar URL
            user.setAvatarUrl(fileName);
            userRepository.save(user);
            
            return ResponseEntity.ok(AvatarUploadResponse.builder()
                    .avatarUrl(fileName)
                    .fileName(fileName)
                    .message("Avatar uploaded successfully")
                    .build());
                    
        } catch (Exception e) {
            throw new RuntimeException("Failed to upload avatar: " + e.getMessage());
        }
    }

    /**
     * Delete avatar for user
     */
    @DeleteMapping("/{id}/avatar")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> deleteAvatar(
            @PathVariable Long id,
            HttpServletRequest request) {
        
        try {
            // Get current user
            String currentEmail = org.springframework.security.core.context.SecurityContextHolder
                    .getContext().getAuthentication().getName();
            com.auth.entity.User currentUser = userRepository.findByEmail(currentEmail)
                    .orElseThrow(() -> new RuntimeException("User không tồn tại"));
            
            // Check if user can delete this avatar (own avatar or admin)
            boolean isAdmin = currentUser.getRoles().stream()
                    .anyMatch(role -> "ROLE_ADMIN".equals(role.getName()));
            
            if (!currentUser.getId().equals(id) && !isAdmin) {
                throw new RuntimeException("Bạn không có quyền xóa avatar cho user này");
            }
            
            // Get user to update
            com.auth.entity.User user = userRepository.findById(id)
                    .orElseThrow(() -> new RuntimeException("User không tồn tại"));
            
            if (user.getAvatarUrl() != null && !user.getAvatarUrl().isEmpty()) {
                // Extract token from request
                String authHeader = request.getHeader("Authorization");
                String token = authHeader != null && authHeader.startsWith("Bearer ") 
                        ? authHeader.substring(7) : null;
                
                if (token != null) {
                    try {
                        fileServiceClient.deleteFile(user.getAvatarUrl(), token);
                    } catch (Exception e) {
                        System.err.println("Failed to delete avatar file: " + e.getMessage());
                    }
                }
                
                // Remove avatar URL from user
                user.setAvatarUrl(null);
                userRepository.save(user);
            }
            
            return ResponseEntity.noContent().build();
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to delete avatar: " + e.getMessage());
        }
    }
}
