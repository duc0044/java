package com.file.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FileUploadResponse {
    private String fileName;
    private String fileUrl;
    private String contentType;
    private Long size;
    private String uploadedBy;
    private String uploadedAt;
}
