package com.auth.service;

import com.auth.dto.*;
import com.auth.entity.*;
import com.auth.repository.PermissionRepository;
import com.auth.repository.RoleRepository;
import com.auth.repository.UserRepository;
import com.auth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthService {
    
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final RedisTemplate<String, String> redisTemplate;
    
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        // Check email exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email đã được sử dụng");
        }
        
        // Check username exists
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username đã được sử dụng");
        }
        
        // Get default role
        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("Default role not found"));
        
        // Create user
        User user = User.builder()
                .email(request.getEmail())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .provider(AuthProvider.LOCAL)
                .build();
        
        user.getRoles().add(userRole);
        user = userRepository.save(user);
        
        // Generate tokens with authorities
        Set<String> authorities = extractAuthoritiesFromUser(user);
        String accessToken = jwtUtil.generateAccessToken(user.getEmail(), user.getUsername(), user.getId(), authorities);
        String refreshToken = jwtUtil.generateRefreshToken(user.getEmail());
        
        // Store refresh token in Redis
        storeRefreshToken(user.getEmail(), refreshToken);
        
        return buildAuthResponse(user, accessToken, refreshToken);
    }
    
    private Set<String> extractAuthoritiesFromUser(User user) {
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
    
    public AuthResponse login(LoginRequest request) {
        // Find user by email or username
        User user = userRepository.findByEmail(request.getEmailOrUsername())
                .or(() -> userRepository.findByUsername(request.getEmailOrUsername()))
                .orElseThrow(() -> new RuntimeException("Email/Username hoặc password không đúng"));
        
        // Check password
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Email/Username hoặc password không đúng");
        }
        
        // Generate tokens with simple authorities
        Set<String> authorities = extractAuthoritiesFromUser(user);
        String accessToken = jwtUtil.generateAccessToken(user.getEmail(), user.getUsername(), user.getId(), authorities);
        String refreshToken = jwtUtil.generateRefreshToken(user.getEmail());
        
        // Store refresh token in Redis
        storeRefreshToken(user.getEmail(), refreshToken);
        
        return buildAuthResponse(user, accessToken, refreshToken);
    }
    
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();
        
        // Validate refresh token
        if (!jwtUtil.validateToken(refreshToken)) {
            throw new RuntimeException("Refresh token không hợp lệ");
        }
        
        // Extract email
        String email = jwtUtil.extractEmail(refreshToken);
        
        // Check if refresh token exists in Redis
        String storedToken = redisTemplate.opsForValue().get("refresh_token:" + email);
        if (storedToken == null || !storedToken.equals(refreshToken)) {
            throw new RuntimeException("Refresh token không hợp lệ hoặc đã hết hạn");
        }
        
        // Find user
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User không tồn tại"));
        
        // Generate new tokens with simple authorities
        Set<String> authorities = extractAuthoritiesFromUser(user);
        String newAccessToken = jwtUtil.generateAccessToken(user.getEmail(), user.getUsername(), user.getId(), authorities);
        String newRefreshToken = jwtUtil.generateRefreshToken(user.getEmail());
        
        // Update refresh token in Redis
        storeRefreshToken(user.getEmail(), newRefreshToken);
        
        return buildAuthResponse(user, newAccessToken, newRefreshToken);
    }
    
    public void logout(String token) {
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
        }
        
        if (jwtUtil.validateToken(token)) {
            String email = jwtUtil.extractEmail(token);
            
            // Remove refresh token from Redis
            redisTemplate.delete("refresh_token:" + email);
            
            // Blacklist access token
            long expiration = jwtUtil.extractExpiration(token).getTime() - System.currentTimeMillis();
            if (expiration > 0) {
                redisTemplate.opsForValue().set(
                    "blacklist:" + token, 
                    "true", 
                    expiration, 
                    TimeUnit.MILLISECONDS
                );
            }
        }
    }
    
    public PageResponse<UserResponse> listUsers(String search, String role, org.springframework.data.domain.Pageable pageable) {
        org.springframework.data.jpa.domain.Specification<User> spec = (root, query, cb) -> {
            java.util.List<jakarta.persistence.criteria.Predicate> predicates = new java.util.ArrayList<>();
            
            if (search != null && !search.isEmpty()) {
                String searchPattern = "%" + search.toLowerCase() + "%";
                predicates.add(cb.or(
                    cb.like(cb.lower(root.get("username")), searchPattern),
                    cb.like(cb.lower(root.get("email")), searchPattern)
                ));
            }
            
            if (role != null && !role.isEmpty()) {
                predicates.add(cb.like(root.get("roles"), "%" + role + "%"));
            }
            
            return cb.and(predicates.toArray(new jakarta.persistence.criteria.Predicate[0]));
        };

        org.springframework.data.domain.Page<User> userPage = userRepository.findAll(spec, pageable);
        return PageResponse.fromPage(userPage, this::mapToUserResponse);
    }

    @Transactional
    public UserResponse createUser(RegisterRequest request) {
        // Check permission
        var authentication = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        boolean hasPermission = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals(com.auth.entity.Permission.USER_CREATE));

        if (!hasPermission) {
            throw new org.springframework.security.access.AccessDeniedException("Bạn không có quyền tạo người dùng");
        }

        // Check if email exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email đã được sử dụng");
        }
        
        // Get default role
        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("Default role not found"));
        
        User user = User.builder()
                .email(request.getEmail())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .provider(AuthProvider.LOCAL)
                .build();
        
        user.getRoles().add(userRole);
        return mapToUserResponse(userRepository.save(user));
    }

    @Transactional
    public UserResponse updateUser(Long id, UpdateUserRequest request) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User không tồn tại"));
        
        if (request.getUsername() != null) {
            validateUsername(request.getUsername(), user.getId());
            user.setUsername(request.getUsername());
        }
        if (request.getEmail() != null) {
            validateEmail(request.getEmail(), user.getId());
            user.setEmail(request.getEmail());
        }
        
        // Update roles
        if (request.getRoles() != null && !request.getRoles().isEmpty()) {
            validateAdminPermission("thay đổi role");
            Set<Role> roles = roleRepository.findByNameIn(request.getRoles());
            if (roles.size() != request.getRoles().size()) {
                throw new RuntimeException("Một số role không hợp lệ");
            }
            user.setRoles(roles);
        }
        
        // Update direct permissions
        if (request.getPermissions() != null) {
            validateAdminPermission("thay đổi permissions");
            if (!request.getPermissions().isEmpty()) {
                Set<PermissionEntity> permissions = permissionRepository.findByNameIn(request.getPermissions());
                if (permissions.size() != request.getPermissions().size()) {
                    throw new RuntimeException("Một số permission không hợp lệ");
                }
                user.setPermissions(permissions);
            } else {
                user.getPermissions().clear();
            }
        }
        
        return mapToUserResponse(userRepository.save(user));
    }

    private void validateAdminPermission(String action) {
        String currentEmail = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication().getName();
        User currentUser = userRepository.findByEmail(currentEmail)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy thông tin người dùng hiện tại"));
        
        boolean isAdmin = currentUser.getRoles().stream()
                .anyMatch(role -> "ROLE_ADMIN".equals(role.getName()));
        
        if (!isAdmin) {
            throw new RuntimeException("Bạn không có quyền " + action);
        }
    }
    
    private void validateEmail(String email, Long userId) {
        if (userRepository.findByEmail(email).isPresent() && 
            !userRepository.findByEmail(email).get().getId().equals(userId)) {
            throw new RuntimeException("Email đã được sử dụng bởi user khác");
        }
    }
    
    private void validateUsername(String username, Long userId) {
        if (userRepository.findByUsername(username).isPresent() && 
            !userRepository.findByUsername(username).get().getId().equals(userId)) {
            throw new RuntimeException("Username đã được sử dụng bởi user khác");
        }
    }

    public void deleteUser(Long id) {
        var authentication = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        
        // Check permission
        boolean hasPermission = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals(com.auth.entity.Permission.USER_DELETE));

        if (!hasPermission) {
            throw new org.springframework.security.access.AccessDeniedException("Bạn không có quyền xóa người dùng");
        }

        String currentEmail = authentication.getName();
        User currentUser = userRepository.findByEmail(currentEmail)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy thông tin người dùng hiện tại"));
        
        if (currentUser.getId().equals(id)) {
            throw new RuntimeException("Bạn không thể tự xóa chính mình");
        }
        
        userRepository.deleteById(id);
    }

    private UserResponse mapToUserResponse(User user) {
        Set<String> roleNames = user.getRoles() != null 
                ? user.getRoles().stream().map(Role::getName).collect(Collectors.toSet())
                : new HashSet<>();
        
        Set<String> allPermissions = new HashSet<>();
        // Add permissions from roles
        if (user.getRoles() != null) {
            user.getRoles().forEach(role -> {
                if (role.getPermissions() != null) {
                    role.getPermissions().forEach(perm -> allPermissions.add(perm.getName()));
                }
            });
        }
        // Add direct user permissions
        if (user.getPermissions() != null) {
            user.getPermissions().forEach(perm -> allPermissions.add(perm.getName()));
        }
        
        return UserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .username(user.getUsername())
                .roles(roleNames)
                .permissions(allPermissions)
                .build();
    }

    private void storeRefreshToken(String email, String refreshToken) {
        redisTemplate.opsForValue().set(
            "refresh_token:" + email,
            refreshToken,
            7,
            TimeUnit.DAYS
        );
    }
    
    private AuthResponse buildAuthResponse(User user, String accessToken, String refreshToken) {
        UserResponse userResponse = mapToUserResponse(user);
        
        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtUtil.getAccessTokenExpiration())
                .user(userResponse)
                .build();
    }
}
