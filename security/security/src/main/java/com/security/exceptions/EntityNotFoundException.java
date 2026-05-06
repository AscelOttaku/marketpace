package com.security.exceptions;

public class EntityNotFoundException extends RuntimeException {

    public EntityNotFoundException(String message) {
        super(message);
    }

    public EntityNotFoundException(String... messages) {
        super(String.join(" ", messages));
    }
}
