package com.auth.client;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class FileServiceClient {

    private final RestTemplate restTemplate;
    
    @Value("${file-service.url:http://file-service:8083}")
    private String fileServiceUrl;

    /**
     * Upload file to file-service
     */
    public String uploadFile(MultipartFile file, String folder, String token) {
        try {
            String uploadUrl = fileServiceUrl + "/api/files/upload";
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.MULTIPART_FORM_DATA);
            headers.setBearerAuth(token);
            
            MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
            body.add("file", new MultipartInputStreamFileResource(file));
            body.add("folder", folder);
            
            HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);
            
            ResponseEntity<Map> response = restTemplate.exchange(
                uploadUrl,
                HttpMethod.POST,
                requestEntity,
                Map.class
            );
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                String fileName = (String) response.getBody().get("fileName");
                log.info("File uploaded successfully: {}", fileName);
                return fileName;
            } else {
                log.error("Failed to upload file. Status: {}", response.getStatusCode());
                throw new RuntimeException("Failed to upload file");
            }
        } catch (Exception e) {
            log.error("Error uploading file to file-service", e);
            throw new RuntimeException("Failed to upload file: " + e.getMessage());
        }
    }

    /**
     * Delete file from file-service
     */
    public void deleteFile(String filePath, String token) {
        try {
            String deleteUrl = fileServiceUrl + "/api/files/" + filePath;
            
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            
            HttpEntity<?> requestEntity = new HttpEntity<>(headers);
            
            restTemplate.exchange(
                deleteUrl,
                HttpMethod.DELETE,
                requestEntity,
                Void.class
            );
            
            log.info("File deleted successfully: {}", filePath);
        } catch (Exception e) {
            log.error("Error deleting file from file-service", e);
            // Don't throw exception, just log it
        }
    }

    /**
     * Helper class for MultipartFile conversion
     */
    private static class MultipartInputStreamFileResource extends ByteArrayResource {

        private final String filename;

        public MultipartInputStreamFileResource(MultipartFile file) throws Exception {
            super(file.getBytes());
            this.filename = file.getOriginalFilename();
        }

        @Override
        public String getFilename() {
            return this.filename;
        }
    }
}
