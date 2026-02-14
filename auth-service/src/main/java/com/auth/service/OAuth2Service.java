package com.auth.service;

import com.auth.dto.AuthResponse;
import com.auth.dto.UserResponse;
import com.auth.entity.*;
import com.auth.repository.RoleRepository; 
import com.auth.repository.UserRepository;
import com.auth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class OAuth2Service extends DefaultOAuth2UserService {
    
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final JwtUtil jwtUtil;
    private final RedisTemplate<String, String> redisTemplate;
    private final RolePermissionService rolePermissionService;
    
    public AuthResponse handleOAuth2User(OAuth2User oAuth2User) {
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");
        
        // Find or create user
        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    // Get default role
                    Role userRole = roleRepository.findByName("ROLE_USER")
                        .orElseThrow(() -> new RuntimeException("Default role not found"));
                        
                    User newUser = User.builder()
                            .email(email)
                            .username(name != null ? name : email.split("@")[0])
                            .provider(AuthProvider.GOOGLE)
                            .roles(Set.of(userRole))
                            .permissions(new HashSet<>())
                            .build();
                    return userRepository.save(newUser);
                });
        
        // Generate tokens with proper authorities
        Set<String> authorities = rolePermissionService.getUserAuthorities(user);
        String accessToken = jwtUtil.generateAccessToken(user.getEmail(), user.getUsername(), user.getId(), authorities);
        String refreshToken = jwtUtil.generateRefreshToken(user.getEmail());
        
        // Store refresh token
        redisTemplate.opsForValue().set(
            "refresh_token:" + user.getEmail(),
            refreshToken,
            7,
            TimeUnit.DAYS
        );
        
        // Build response  
        String rolesString = user.getRoles().stream()
            .map(Role::getName)
            .collect(Collectors.joining(","));
            
        String permissionsString = user.getPermissions().stream()
            .map(PermissionEntity::getName)
            .collect(Collectors.joining(","));
        
        UserResponse userResponse = UserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .username(user.getUsername())
                .roles(rolesString)
                .permissions(permissionsString.isEmpty() ? null : permissionsString)
                .build();
        
        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtUtil.getAccessTokenExpiration())
                .user(userResponse)
                .build();
    }
}
