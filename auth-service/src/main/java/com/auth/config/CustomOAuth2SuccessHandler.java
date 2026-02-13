package com.auth.config;

import com.auth.dto.AuthResponse;
import com.auth.service.OAuth2Service;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class CustomOAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final OAuth2Service oAuth2Service;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        AuthResponse authResponse = oAuth2Service.handleOAuth2User(oAuth2User);

        // Redirect to frontend with tokens
        String redirectUrl = String.format(
            "http://localhost:3000/auth/callback?accessToken=%s&refreshToken=%s",
            authResponse.getAccessToken(),
            authResponse.getRefreshToken()
        );

        response.sendRedirect(redirectUrl);
    }
}
