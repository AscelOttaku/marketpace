package com.market.helper.other;

import com.market.exceptions.ValidationException;
import org.springframework.http.HttpStatus;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public class ErrorsBuilder {

    private ErrorsBuilder() {
    }

    public static void buildError(BindingResult bindingResult) {
        Optional.of(bindingResult.getFieldErrors())
                .filter(errors -> !errors.isEmpty())
                .ifPresent(fieldErrors -> {
                    throw new ValidationException(buildErrorMessage(fieldErrors));
                });
    }

    public static String buildErrorMessage(BindingResult bindingResult) {
        return Optional.of(bindingResult.getFieldErrors())
                .filter(errors -> !errors.isEmpty())
                .map(ErrorsBuilder::buildErrorMessage)
                .orElse(null);
    }

    public static String buildErrorMessage(List<FieldError> fieldErrors) {
        return Map.of(
                "timestamp", LocalDateTime.now(),
                "status", HttpStatus.BAD_REQUEST.value(),
                "errors", fieldErrors.stream()
                        .map(err -> Map.of(
                                "field", err.getField(),
                                "message", Objects.requireNonNull(err.getDefaultMessage())
                        ))
                        .toList()
        ).toString();
    }
}
