package com.auth.entity;

public class Permission {
    // User Management Permissions
    public static final String USER_READ = "user:read";
    public static final String USER_CREATE = "user:create";
    public static final String USER_UPDATE = "user:update";
    public static final String USER_DELETE = "user:delete";
    
    // Report Management Permissions (example new feature)
    public static final String REPORT_READ = "report:read";
    public static final String REPORT_CREATE = "report:create";
    public static final String REPORT_UPDATE = "report:update";
    public static final String REPORT_DELETE = "report:delete";
    public static final String REPORT_EXPORT = "report:export";
    
    // Order Management Permissions (example new feature)
    public static final String ORDER_READ = "order:read";
    public static final String ORDER_CREATE = "order:create";
    public static final String ORDER_UPDATE = "order:update";
    public static final String ORDER_DELETE = "order:delete";
    public static final String ORDER_APPROVE = "order:approve";
    
    // System Administration Permissions
    public static final String SYSTEM_CONFIG = "system:config";
    public static final String SYSTEM_BACKUP = "system:backup";
    public static final String AUDIT_READ = "audit:read";
}
