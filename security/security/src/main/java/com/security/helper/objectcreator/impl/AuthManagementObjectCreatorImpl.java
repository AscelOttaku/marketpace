package com.security.helper.objectcreator.impl;

import com.google.gson.Gson;
import com.security.dto.request.auth.RefreshAccessTokenResponse;
import com.security.dto.response.auth.AuthResponse;
import com.security.dto.response.auth.UserDetailsResponse;
import com.security.dto.response.common.Response;
import com.security.helper.objectcreator.AuthManagementObjectCreator;
import com.security.model.User;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthManagementObjectCreatorImpl implements AuthManagementObjectCreator {

    Gson gson;

    @Override
    public ResponseEntity<Response> createAuthenticateSuccessResponse(String accessToken,
                                                                      String refreshToken) {
        return ResponseEntity.ok().body(
                Response.builder()
                        .data(AuthResponse.builder()
                                .accessToken(accessToken)
                                .refreshToken(refreshToken)
                                .build())
                        .build());
    }

    @Override
    public ResponseEntity<Response> createRefreshAccessTokenResponse(String accessToken) {
        return ResponseEntity.ok()
                .body(Response.builder()
                        .data(RefreshAccessTokenResponse.builder()
                                .accessToken(accessToken)
                                .build())
                        .build());
    }

    @Override
    public String createAccessDeniedResponse(String message) {
        log.error(message);
        return gson.toJson(Response.builder()
                .message(message)
                .build());
    }

    @Override
    public ResponseEntity<UserDetailsResponse> createUserDetailsResponse(User user) {
        return ResponseEntity.ok().body(UserDetailsResponse.builder()
                .email(user.getEmail())
                .role(user.getRole())
                .password(user.getPassword())
                .build());
    }
}
