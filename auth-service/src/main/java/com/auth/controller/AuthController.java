package com.auth.controller;

import com.auth.dto.*;
import com.auth.service.AuthService;
import com.auth.service.OAuth2Service;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    
    private final AuthService authService;
    private final OAuth2Service oAuth2Service;
    
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
    
    @GetMapping("/oauth2/callback/google")
    public void handleGoogleCallback(
            @AuthenticationPrincipal OAuth2User oAuth2User,
            HttpServletResponse response) throws IOException {
        
        AuthResponse authResponse = oAuth2Service.handleOAuth2User(oAuth2User);
        
        // Redirect to frontend with tokens (mobile/web will handle this)
        String redirectUrl = String.format(
            "http://localhost:3000/auth/callback?accessToken=%s&refreshToken=%s",
            authResponse.getAccessToken(),
            authResponse.getRefreshToken()
        );
        
        response.sendRedirect(redirectUrl);
    }
    
    @GetMapping("/test")
    public ResponseEntity<String> test() {
        return ResponseEntity.ok("Auth Service is running!");
    }
}
