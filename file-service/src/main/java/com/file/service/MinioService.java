package com.file.service;

import io.minio.*;
import io.minio.http.Method;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.InputStream;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class MinioService {

    private final MinioClient minioClient;
    
    @Value("${minio.bucket-name}")
    private String bucketName;

    /**
     * Upload file to MinIO
     */
    public String uploadFile(MultipartFile file, String folder) {
        try {
            String originalFilename = file.getOriginalFilename();
            String extension = "";
            if (originalFilename != null && originalFilename.contains(".")) {
                extension = originalFilename.substring(originalFilename.lastIndexOf("."));
            }
            
            // Generate unique filename
            String fileName = folder + "/" + UUID.randomUUID().toString() + extension;
            
            InputStream inputStream = file.getInputStream();
            
            minioClient.putObject(
                PutObjectArgs.builder()
                    .bucket(bucketName)
                    .object(fileName)
                    .stream(inputStream, file.getSize(), -1)
                    .contentType(file.getContentType())
                    .build()
            );
            
            log.info("File uploaded successfully: {}", fileName);
            return fileName;
        } catch (Exception e) {
            log.error("Error uploading file", e);
            throw new RuntimeException("Failed to upload file: " + e.getMessage());
        }
    }

    /**
     * Download file from MinIO
     */
    public InputStream downloadFile(String fileName) {
        try {
            return minioClient.getObject(
                GetObjectArgs.builder()
                    .bucket(bucketName)
                    .object(fileName)
                    .build()
            );
        } catch (Exception e) {
            log.error("Error downloading file: {}", fileName, e);
            throw new RuntimeException("Failed to download file: " + e.getMessage());
        }
    }

    /**
     * Delete file from MinIO
     */
    public void deleteFile(String fileName) {
        try {
            minioClient.removeObject(
                RemoveObjectArgs.builder()
                    .bucket(bucketName)
                    .object(fileName)
                    .build()
            );
            log.info("File deleted successfully: {}", fileName);
        } catch (Exception e) {
            log.error("Error deleting file: {}", fileName, e);
            throw new RuntimeException("Failed to delete file: " + e.getMessage());
        }
    }

    /**
     * Get presigned URL for file (temporary access)
     */
    public String getPresignedUrl(String fileName, int expiryMinutes) {
        try {
            return minioClient.getPresignedObjectUrl(
                GetPresignedObjectUrlArgs.builder()
                    .method(Method.GET)
                    .bucket(bucketName)
                    .object(fileName)
                    .expiry(expiryMinutes, TimeUnit.MINUTES)
                    .build()
            );
        } catch (Exception e) {
            log.error("Error generating presigned URL for: {}", fileName, e);
            throw new RuntimeException("Failed to generate presigned URL: " + e.getMessage());
        }
    }

    /**
     * Get file metadata
     */
    public Map<String, Object> getFileMetadata(String fileName) {
        try {
            StatObjectResponse stat = minioClient.statObject(
                StatObjectArgs.builder()
                    .bucket(bucketName)
                    .object(fileName)
                    .build()
            );
            
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("fileName", fileName);
            metadata.put("size", stat.size());
            metadata.put("contentType", stat.contentType());
            metadata.put("lastModified", stat.lastModified());
            metadata.put("etag", stat.etag());
            
            return metadata;
        } catch (Exception e) {
            log.error("Error getting file metadata: {}", fileName, e);
            throw new RuntimeException("Failed to get file metadata: " + e.getMessage());
        }
    }

    /**
     * Check if file exists
     */
    public boolean fileExists(String fileName) {
        try {
            minioClient.statObject(
                StatObjectArgs.builder()
                    .bucket(bucketName)
                    .object(fileName)
                    .build()
            );
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
