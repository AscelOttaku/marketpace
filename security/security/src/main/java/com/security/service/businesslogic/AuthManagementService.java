package com.security.service.businesslogic;

import com.security.dto.request.auth.UserAuthenticateRequest;
import com.security.dto.response.common.Response;
import org.springframework.http.ResponseEntity;

public interface AuthManagementService {
    ResponseEntity<Response> login(UserAuthenticateRequest request);

    ResponseEntity<Response> refreshToken();
}
