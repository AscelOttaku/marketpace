package com.security.helper.objectcreator.impl;

import com.google.gson.Gson;
import com.security.dto.response.common.Response;
import com.security.helper.objectcreator.ErrorObjectCreator;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import static lombok.AccessLevel.PRIVATE;

@Slf4j
@Component
@RequiredArgsConstructor
@FieldDefaults(level = PRIVATE, makeFinal = true)
public class ErrorObjectCreatorImpl implements ErrorObjectCreator {

    Gson gson;

    @Override
    public String createAccessDeniedResponse(String message) {
        log.error(message);
        return gson.toJson(Response.builder()
                .message(message)
                .build());
    }

    @Override
    public String createUnauthorizedResponse(String message) {
        log.error(message);
        return gson.toJson(Response.builder()
                .message(message)
                .build());
    }
}
