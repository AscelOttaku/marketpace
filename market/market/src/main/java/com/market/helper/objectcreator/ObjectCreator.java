package com.market.helper.objectcreator;

import com.market.dto.response.common.Response;
import org.springframework.http.ResponseEntity;

public interface ObjectCreator {

    default ResponseEntity<Response> createSuccessResponse() {
        return ResponseEntity.ok().body(
                Response.builder()
                        .status(Response.Status.SUCCESS)
                        .build());
    }

    default ResponseEntity<Response> createSuccessResponse(Object object) {
        return ResponseEntity.ok().body(
                Response.builder()
                        .status(Response.Status.SUCCESS)
                        .data(object)
                        .build());
    }

    default ResponseEntity<Response> createSuccessResponse(Object object, String message) {
        return ResponseEntity.ok().body(
                Response.builder()
                        .status(Response.Status.SUCCESS)
                        .data(object)
                        .message(message)
                        .build());
    }

    default ResponseEntity<Response> createErrorResponse(Object object) {
        return ResponseEntity.ok().body(
                Response.builder()
                        .status(Response.Status.ERROR)
                        .data(object)
                        .build());
    }

    default ResponseEntity<Response> createErrorResponse(Object object, String message) {
        return ResponseEntity.ok().body(
                Response.builder()
                        .status(Response.Status.ERROR)
                        .data(object)
                        .message(message)
                        .build());
    }

    default ResponseEntity<Response> createFailResponse(Object object) {
        return ResponseEntity.badRequest().body(
                Response.builder()
                        .status(Response.Status.FAILED)
                        .data(object)
                        .build());
    }

    default ResponseEntity<Response> createFailResponse(Object object, String message) {
        return ResponseEntity.badRequest().body(
                Response.builder()
                        .status(Response.Status.FAILED)
                        .data(object)
                        .message(message)
                        .build());
    }
}
