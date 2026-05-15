package com.security.service.businesslogic;

import com.security.dto.request.auth.ChangePasswordRequest;
import com.security.dto.request.auth.UserAuthenticateRequest;
import com.security.dto.response.auth.UserDetailsResponse;
import com.security.dto.response.common.Response;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;

public interface AuthManagementService {
    ResponseEntity<Response> login(UserAuthenticateRequest request);

    ResponseEntity<Response> refreshToken();

    ResponseEntity<UserDetailsResponse> validate();

    ResponseEntity<Response> changePassword(ChangePasswordRequest request,
                                            BindingResult bindingResult);
}
