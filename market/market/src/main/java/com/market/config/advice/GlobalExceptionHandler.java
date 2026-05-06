package com.market.config.advice;

import com.market.dto.response.common.Response;
import com.market.exceptions.EntityNotFoundException;
import com.market.exceptions.FileOperationException;
import com.market.exceptions.ValidationException;
import com.market.helper.objectcreator.ErrorObjectCreator;
import com.market.helper.other.ErrorsBuilder;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
public class GlobalExceptionHandler {
    ErrorObjectCreator objectCreator;

    @ExceptionHandler(ValidationException.class)
    public ResponseEntity<Response> handleValidationException(ValidationException e) {
        log.error(e.getMessage());
        return objectCreator.createFailResponse(e.getMessage());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Response> handleException(Exception e) {
        log.error(e.getMessage());
        return objectCreator.createErrorResponse(e.getMessage());
    }

    @ExceptionHandler(FileOperationException.class)
    public ResponseEntity<Response> handleFileOperationException(FileOperationException e) {
        log.error(e.getMessage());
        return objectCreator.createFailResponse(e.getMessage());
    }

    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<Response> handleEntityNotFoundException(EntityNotFoundException e) {
        log.error(e.getMessage());
        return objectCreator.createFailResponse(e.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Response> handleMethodArgumentNotValidException(MethodArgumentNotValidException e) {
        log.error(e.getMessage());
        return objectCreator.createFailResponse(ErrorsBuilder
                .buildErrorMessage(e.getBindingResult()));
    }
}
