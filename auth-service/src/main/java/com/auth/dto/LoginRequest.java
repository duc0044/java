package com.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {
    
    @NotBlank(message = "Email hoặc username không được để trống")
    private String emailOrUsername;
    
    @NotBlank(message = "Password không được để trống")
    private String password;
}
