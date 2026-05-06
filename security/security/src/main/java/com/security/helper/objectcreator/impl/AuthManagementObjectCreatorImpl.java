package com.security.helper.objectcreator.impl;

import com.security.dto.request.auth.RefreshAccessTokenResponse;
import com.security.dto.response.auth.AuthResponse;
import com.security.dto.response.common.Response;
import com.security.helper.objectcreator.AuthManagementObjectCreator;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthManagementObjectCreatorImpl implements AuthManagementObjectCreator {

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
}
