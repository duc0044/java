package com.file.controller;

import com.file.dto.FileUploadResponse;
import com.file.service.MinioService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.InputStream;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/files")
@RequiredArgsConstructor
public class FileController {

    private final MinioService minioService;

    /**
     * Upload file
     */
    @PostMapping("/upload")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<FileUploadResponse> uploadFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "folder", defaultValue = "general") String folder) {
        
        try {
            String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
            
            log.info("Uploading file: {} by user: {}", file.getOriginalFilename(), currentUser);
            
            String fileName = minioService.uploadFile(file, folder);
            
            FileUploadResponse response = FileUploadResponse.builder()
                    .fileName(fileName)
                    .fileUrl("/api/files/download/" + fileName)
                    .contentType(file.getContentType())
                    .size(file.getSize())
                    .uploadedBy(currentUser)
                    .uploadedAt(LocalDateTime.now().toString())
                    .build();
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error uploading file", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Download file by path query parameter
     */
    @GetMapping("/download")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<InputStreamResource> downloadFileByPath(
            @RequestParam String path) {
        
        try {
            log.info("Downloading file from path: {}", path);
            
            InputStream inputStream = minioService.downloadFile(path);
            Map<String, Object> metadata = minioService.getFileMetadata(path);
            
            String filename = path.contains("/") ? path.substring(path.lastIndexOf("/") + 1) : path;
            
            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType((String) metadata.get("contentType")))
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                    .body(new InputStreamResource(inputStream));
        } catch (Exception e) {
            log.error("Error downloading file by path", e);
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Download file by path parameters
     */
    @GetMapping("/download/{folder}/{filename}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<InputStreamResource> downloadFile(
            @PathVariable String folder,
            @PathVariable String filename) {
        
        try {
            String fullPath = folder + "/" + filename;
            InputStream inputStream = minioService.downloadFile(fullPath);
            
            Map<String, Object> metadata = minioService.getFileMetadata(fullPath);
            
            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType((String) metadata.get("contentType")))
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                    .body(new InputStreamResource(inputStream));
        } catch (Exception e) {
            log.error("Error downloading file", e);
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Get presigned URL for file
     */
    @GetMapping("/url/{folder}/{filename}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, String>> getFileUrl(
            @PathVariable String folder,
            @PathVariable String filename,
            @RequestParam(value = "expiry", defaultValue = "60") int expiryMinutes) {
        
        try {
            String fullPath = folder + "/" + filename;
            String url = minioService.getPresignedUrl(fullPath, expiryMinutes);
            
            Map<String, String> response = new HashMap<>();
            response.put("url", url);
            response.put("expiresInMinutes", String.valueOf(expiryMinutes));
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error generating file URL", e);
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Delete file
     */
    @DeleteMapping("/{folder}/{filename}")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('file:delete')")
    public ResponseEntity<Map<String, String>> deleteFile(
            @PathVariable String folder,
            @PathVariable String filename) {
        
        try {
            String fullPath = folder + "/" + filename;
            String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
            
            log.info("Deleting file: {} by user: {}", fullPath, currentUser);
            
            minioService.deleteFile(fullPath);
            
            Map<String, String> response = new HashMap<>();
            response.put("message", "File deleted successfully");
            response.put("fileName", fullPath);
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error deleting file", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Get file metadata
     */
    @GetMapping("/metadata/{folder}/{filename}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> getFileMetadata(
            @PathVariable String folder,
            @PathVariable String filename) {
        
        try {
            String fullPath = folder + "/" + filename;
            Map<String, Object> metadata = minioService.getFileMetadata(fullPath);
            
            return ResponseEntity.ok(metadata);
        } catch (Exception e) {
            log.error("Error getting file metadata", e);
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Check if file exists
     */
    @GetMapping("/exists/{folder}/{filename}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Boolean>> checkFileExists(
            @PathVariable String folder,
            @PathVariable String filename) {
        
        String fullPath = folder + "/" + filename;
        boolean exists = minioService.fileExists(fullPath);
        
        Map<String, Boolean> response = new HashMap<>();
        response.put("exists", exists);
        
        return ResponseEntity.ok(response);
    }
}
