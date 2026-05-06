package com.security.config.advice;

import com.security.dto.response.common.Response;
import com.security.exceptions.EntityNotFoundException;
import com.security.helper.objectcreator.ErrorObjectCreator;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@Slf4j
@ControllerAdvice
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class GlobalExceptionHandler {
    ErrorObjectCreator objectCreator;

    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<Response> handleEntityNotFoundException(EntityNotFoundException e) {
        log.error(e.getMessage());
        return objectCreator.createFailResponse(e.getMessage());
    }
}

