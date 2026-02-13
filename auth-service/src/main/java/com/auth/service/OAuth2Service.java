package com.auth.service;

import com.auth.dto.AuthResponse;
import com.auth.dto.UserResponse;
import com.auth.entity.AuthProvider;
import com.auth.entity.User;
import com.auth.repository.UserRepository;
import com.auth.util.AuthorityUtils;
import com.auth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class OAuth2Service extends DefaultOAuth2UserService {
    
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final RedisTemplate<String, String> redisTemplate;
    
    public AuthResponse handleOAuth2User(OAuth2User oAuth2User) {
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");
        
        // Find or create user
        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = User.builder()
                            .email(email)
                            .username(name != null ? name : email.split("@")[0])
                            .provider(AuthProvider.GOOGLE)
                            .roles("ROLE_USER")
                            .build();
                    return userRepository.save(newUser);
                });
        
        // Generate tokens
        String accessToken = jwtUtil.generateAccessToken(user.getEmail(), user.getUsername(), user.getId(), AuthorityUtils.getAuthorities(user.getRoles()));
        String refreshToken = jwtUtil.generateRefreshToken(user.getEmail());
        
        // Store refresh token
        redisTemplate.opsForValue().set(
            "refresh_token:" + user.getEmail(),
            refreshToken,
            7,
            TimeUnit.DAYS
        );
        
        // Build response
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
