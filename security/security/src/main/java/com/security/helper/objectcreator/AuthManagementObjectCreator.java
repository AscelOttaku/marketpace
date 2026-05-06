package com.security.helper.objectcreator;

import com.security.dto.response.common.Response;
import org.springframework.http.ResponseEntity;

public interface AuthManagementObjectCreator extends ObjectCreator {
    ResponseEntity<Response> createAuthenticateSuccessResponse(String accessToken,
                                                               String refreshToken);
}
