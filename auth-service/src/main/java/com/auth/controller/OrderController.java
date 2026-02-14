package com.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import java.util.*;

/**
 * Example controller demonstrating new permission system
 * For Order Management feature
 */
@RestController
@RequestMapping("/api/orders")
public class OrderController {

    @GetMapping
    @PreAuthorize("hasAuthority('order:read')")
    public ResponseEntity<Map<String, Object>> getAllOrders(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(required = false) String status) {
        
        // Simulate order data
        Map<String, Object> response = new HashMap<>();
        response.put("orders", Arrays.asList(
            Map.of("id", 1, "customerName", "John Doe", "status", "pending", "amount", 100.50),
            Map.of("id", 2, "customerName", "Jane Smith", "status", "approved", "amount", 250.75)
        ));
        response.put("page", page);
        response.put("totalElements", 2);
        
        return ResponseEntity.ok(response);
    }

    @PostMapping
    @PreAuthorize("hasAuthority('order:create')")
    public ResponseEntity<Map<String, Object>> createOrder(@RequestBody Map<String, Object> orderData) {
        
        String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
        
        // Create order logic here
        Map<String, Object> newOrder = new HashMap<>();
        newOrder.put("id", 3);
        newOrder.put("customerName", orderData.get("customerName"));
        newOrder.put("amount", orderData.get("amount"));
        newOrder.put("status", "pending");
        newOrder.put("createdBy", currentUser);
        
        return ResponseEntity.ok(newOrder);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('order:update')")
    public ResponseEntity<Map<String, Object>> updateOrder(
            @PathVariable Long id, 
            @RequestBody Map<String, Object> orderData) {
        
        // Update order logic here
        Map<String, Object> updatedOrder = new HashMap<>();
        updatedOrder.put("id", id);
        updatedOrder.put("customerName", orderData.get("customerName"));
        updatedOrder.put("amount", orderData.get("amount"));
        updatedOrder.put("status", "updated");
        
        return ResponseEntity.ok(updatedOrder);
    }

    @PostMapping("/{id}/approve")
    @PreAuthorize("hasAuthority('order:approve')")
    public ResponseEntity<Map<String, Object>> approveOrder(@PathVariable Long id) {
        
        String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
        
        // Approve order logic here
        Map<String, Object> approvedOrder = new HashMap<>();
        approvedOrder.put("id", id);
        approvedOrder.put("status", "approved");
        approvedOrder.put("approvedBy", currentUser);
        approvedOrder.put("approvedAt", new Date());
        
        return ResponseEntity.ok(approvedOrder);
    }

    @PostMapping("/{id}/reject")
    @PreAuthorize("hasAuthority('order:approve')")
    public ResponseEntity<Map<String, Object>> rejectOrder(
            @PathVariable Long id, 
            @RequestBody Map<String, String> reason) {
        
        String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
        
        // Reject order logic here
        Map<String, Object> rejectedOrder = new HashMap<>();
        rejectedOrder.put("id", id);
        rejectedOrder.put("status", "rejected");
        rejectedOrder.put("rejectedBy", currentUser);
        rejectedOrder.put("rejectedAt", new Date());
        rejectedOrder.put("reason", reason.get("reason"));
        
        return ResponseEntity.ok(rejectedOrder);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('order:delete')")
    public ResponseEntity<Void> deleteOrder(@PathVariable Long id) {
        
        // Delete order logic here (usually only admins can do this)
        return ResponseEntity.noContent().build();
    }
}