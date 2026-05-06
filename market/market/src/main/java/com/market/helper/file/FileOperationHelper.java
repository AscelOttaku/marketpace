package com.market.helper.file;

import com.market.exceptions.FileOperationException;
import org.springframework.http.MediaType;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

public class FileOperationHelper {
    private static final List<String> ALLOWED_IMAGE_TYPES;

    static {
        ALLOWED_IMAGE_TYPES = List.of("image/jpeg", "image/png");
    }

    private FileOperationHelper() {
    }

    public static byte[] readFile(MultipartFile file) {
        if (file == null || file.isEmpty())
            return new byte[0];

        String contentType = file.getContentType();
        if (contentType == null || !ALLOWED_IMAGE_TYPES.contains(contentType.toLowerCase())) {
            throw new FileOperationException("Недопустимый формат файла. Разрешены только: " + ALLOWED_IMAGE_TYPES);
        }

        try {
            return file.getBytes();
        } catch (IOException e) {
            throw new FileOperationException(e.getMessage(), e);
        }
    }

    public static String defineImgExtension(byte[] img) {
        if (img[0] == (byte) 0x89 && img[1] == 0x50) return MediaType.IMAGE_PNG_VALUE;
        if (img[0] == (byte) 0xFF && img[1] == (byte) 0xD8) return MediaType.IMAGE_JPEG_VALUE;
        else return MediaType.APPLICATION_OCTET_STREAM_VALUE;
    }
}
