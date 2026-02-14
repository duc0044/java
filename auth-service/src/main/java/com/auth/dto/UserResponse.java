package com.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserResponse {
    
    private Long id;
    private String email;
    private String username;
    private Set<String> roles;  // Changed to Set<String> for role names
    private Set<String> permissions;  // Changed to Set<String> for permission names
}
