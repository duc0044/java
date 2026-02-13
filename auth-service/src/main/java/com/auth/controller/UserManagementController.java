package com.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/users")
@lombok.RequiredArgsConstructor
public class UserManagementController {

    private final com.auth.service.AuthService authService;

    @GetMapping
    @PreAuthorize("hasAuthority('user:read')")
    public ResponseEntity<com.auth.dto.PageResponse<com.auth.dto.UserResponse>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(required = false) String search,
            @RequestParam(required = false) String role) {
        org.springframework.data.domain.Pageable pageable = org.springframework.data.domain.PageRequest.of(page, size);
        return ResponseEntity.ok(authService.listUsers(search, role, pageable));
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
