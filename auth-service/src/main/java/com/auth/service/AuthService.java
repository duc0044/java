package com.auth.service;

import com.auth.dto.*;
import com.auth.entity.AuthProvider;
import com.auth.entity.User;
import com.auth.repository.UserRepository;
import com.auth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class AuthService {
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final RedisTemplate<String, String> redisTemplate;
    
    public AuthResponse register(RegisterRequest request) {
        // Check email exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email đã được sử dụng");
        }
        
        // Check username exists
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username đã được sử dụng");
        }
        
        // Create user
        User user = User.builder()
                .email(request.getEmail())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .provider(AuthProvider.LOCAL)
                .roles("ROLE_USER")
                .build();
        
        user = userRepository.save(user);
        
        // Generate tokens
        String accessToken = jwtUtil.generateAccessToken(user.getEmail(), user.getUsername(), user.getId());
        String refreshToken = jwtUtil.generateRefreshToken(user.getEmail());
        
        // Store refresh token in Redis
        storeRefreshToken(user.getEmail(), refreshToken);
        
        return buildAuthResponse(user, accessToken, refreshToken);
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
        
        // Generate tokens
        String accessToken = jwtUtil.generateAccessToken(user.getEmail(), user.getUsername(), user.getId());
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
        
        // Generate new tokens
        String newAccessToken = jwtUtil.generateAccessToken(user.getEmail(), user.getUsername(), user.getId());
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
    
    private void storeRefreshToken(String email, String refreshToken) {
        redisTemplate.opsForValue().set(
            "refresh_token:" + email,
            refreshToken,
            7,
            TimeUnit.DAYS
        );
    }
    
    private AuthResponse buildAuthResponse(User user, String accessToken, String refreshToken) {
        UserResponse userResponse = UserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .username(user.getUsername())
                .roles(user.getRoles())
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
