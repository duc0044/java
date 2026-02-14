package com.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import java.util.*;

/**
 * Example controller demonstrating new permission system
 * For Report Management feature
 */
@RestController
@RequestMapping("/api/reports")
public class ReportController {

    @GetMapping
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('report:read')")
    public ResponseEntity<Map<String, Object>> getAllReports(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        
        // Simulate report data
        Map<String, Object> response = new HashMap<>();
        response.put("reports", Arrays.asList(
            Map.of("id", 1, "name", "Monthly Sales Report", "type", "sales"),
            Map.of("id", 2, "name", "User Activity Report", "type", "activity")
        ));
        response.put("page", page);
        response.put("totalElements", 2);
        
        return ResponseEntity.ok(response);
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('report:create')")
    public ResponseEntity<Map<String, Object>> createReport(@RequestBody Map<String, Object> reportData) {
        
        // Create report logic here
        Map<String, Object> newReport = new HashMap<>();
        newReport.put("id", 3);
        newReport.put("name", reportData.get("name"));
        newReport.put("type", reportData.get("type"));
        newReport.put("status", "created");
        
        return ResponseEntity.ok(newReport);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('report:update')")
    public ResponseEntity<Map<String, Object>> updateReport(
            @PathVariable Long id, 
            @RequestBody Map<String, Object> reportData) {
        
        // Update report logic here
        Map<String, Object> updatedReport = new HashMap<>();
        updatedReport.put("id", id);
        updatedReport.put("name", reportData.get("name"));
        updatedReport.put("status", "updated");
        
        return ResponseEntity.ok(updatedReport);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('report:delete')")
    public ResponseEntity<Void> deleteReport(@PathVariable Long id) {
        
        // Delete report logic here
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/export")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('report:export')")
    public ResponseEntity<Map<String, Object>> exportReport(@PathVariable Long id) {
        
        // Export report logic here
        Map<String, Object> exportInfo = new HashMap<>();
        exportInfo.put("reportId", id);
        exportInfo.put("exportUrl", "/downloads/report-" + id + ".pdf");
        exportInfo.put("status", "exported");
        
        return ResponseEntity.ok(exportInfo);
    }
}