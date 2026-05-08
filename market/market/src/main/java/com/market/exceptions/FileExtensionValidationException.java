package com.market.exceptions;

public class FileExtensionValidationException extends RuntimeException {
    public FileExtensionValidationException(String message) {
        super(message);
    }
}
