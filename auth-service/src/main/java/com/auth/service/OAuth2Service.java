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
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class OAuth2Service extends DefaultOAuth2UserService {
    
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final JwtUtil jwtUtil;
    private final RedisTemplate<String, String> redisTemplate;
    
    @Transactional
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
                            .build();
                    newUser.getRoles().add(userRole);
                    return userRepository.save(newUser);
                });
        
        // Generate tokens with authorities
        Set<String> authorities = extractAuthoritiesFromUser(user);
        String accessToken = jwtUtil.generateAccessToken(user.getEmail(), user.getUsername(), user.getId(), authorities);
        String refreshToken = jwtUtil.generateRefreshToken(user.getEmail());
        
        // Store refresh token
        redisTemplate.opsForValue().set(
            "refresh_token:" + user.getEmail(),
            refreshToken,
            7,
            TimeUnit.DAYS
        );
        
        // Build user response
        Set<String> roleNames = user.getRoles() != null 
                ? user.getRoles().stream().map(Role::getName).collect(Collectors.toSet())
                : new HashSet<>();
        
        Set<String> allPermissions = new HashSet<>();
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
        
        // Build response  
        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtUtil.getAccessTokenExpiration())
                .user(UserResponse.builder()
                        .id(user.getId())
                        .email(user.getEmail())
                        .username(user.getUsername())
                        .roles(roleNames)
                        .permissions(allPermissions)
                        .build())
                .build();
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
}
