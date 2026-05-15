package com.security.helper.objectcreator;

import com.security.dto.request.auth.ChangePasswordRequest;
import com.security.dto.response.auth.UserDetailsResponse;
import com.security.dto.response.common.Response;
import com.security.model.User;
import org.springframework.http.ResponseEntity;

public interface AuthManagementObjectCreator extends ObjectCreator {
    ResponseEntity<Response> createAuthenticateSuccessResponse(String accessToken,
                                                               String refreshToken);

    ResponseEntity<Response> createRefreshAccessTokenResponse(String accessToken);

    String createAccessDeniedResponse(String message);

    ResponseEntity<UserDetailsResponse> createUserDetailsResponse(User user);

    User createUserUpdateModel(User user, ChangePasswordRequest request);
}
