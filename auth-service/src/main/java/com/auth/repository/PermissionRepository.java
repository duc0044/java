package com.auth.repository;

import com.auth.entity.PermissionEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.Set;
import java.util.List;

@Repository
public interface PermissionRepository extends JpaRepository<PermissionEntity, Long> {
    
    Optional<PermissionEntity> findByName(String name);
    
    boolean existsByName(String name);
    
    @Query("SELECT p FROM PermissionEntity p WHERE p.name IN :names")
    Set<PermissionEntity> findByNameIn(Set<String> names);
    
    List<PermissionEntity> findByCategory(String category);
    
    Page<PermissionEntity> findByCategory(String category, Pageable pageable);
    
    @Query("SELECT DISTINCT p.category FROM PermissionEntity p")
    List<String> findDistinctCategories();
}