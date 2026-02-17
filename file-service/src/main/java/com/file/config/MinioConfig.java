package com.file.config;

import io.minio.BucketExistsArgs;
import io.minio.MakeBucketArgs;
import io.minio.MinioClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Slf4j
@Configuration
public class MinioConfig {

    @Value("${minio.endpoint}")
    private String endpoint;

    @Value("${minio.access-key}")
    private String accessKey;

    @Value("${minio.secret-key}")
    private String secretKey;

    @Value("${minio.bucket-name}")
    private String bucketName;

    @Value("${minio.auto-create-bucket:true}")
    private boolean autoCreateBucket;

    @Bean
    public MinioClient minioClient() {
        try {
            MinioClient minioClient = MinioClient.builder()
                    .endpoint(endpoint)
                    .credentials(accessKey, secretKey)
                    .build();

            // Auto-create bucket if enabled
            if (autoCreateBucket) {
                boolean bucketExists = minioClient.bucketExists(
                        BucketExistsArgs.builder().bucket(bucketName).build()
                );
                
                if (!bucketExists) {
                    minioClient.makeBucket(
                            MakeBucketArgs.builder().bucket(bucketName).build()
                    );
                    log.info("Created MinIO bucket: {}", bucketName);
                } else {
                    log.info("MinIO bucket already exists: {}", bucketName);
                }
            }

            log.info("MinIO client initialized successfully. Endpoint: {}", endpoint);
            return minioClient;
        } catch (Exception e) {
            log.error("Error initializing MinIO client", e);
            throw new RuntimeException("Could not initialize MinIO client", e);
        }
    }

    @Bean
    public String minioBucketName() {
        return bucketName;
    }
}
