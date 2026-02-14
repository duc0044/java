package com.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "permissions")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PermissionEntity {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true, nullable = false, length = 100)
    private String name; // user:read, user:create, etc.
    
    @Column(length = 255)
    private String description;
    
    @Column(length = 50)
    private String category; // User Management, Report Management, etc.
    
    @ManyToMany(mappedBy = "permissions")
    private Set<Role> roles = new HashSet<>();
    
    @ManyToMany(mappedBy = "permissions")
    private Set<User> users = new HashSet<>();
}