package com.security.api;

import com.security.dto.request.auth.UserAuthenticateRequest;
import com.security.dto.response.common.Response;
import com.security.service.businesslogic.AuthManagementService;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenticationApi {

    AuthManagementService authManagementService;

    @PostMapping("/login")
    public ResponseEntity<Response> login(@RequestBody @Valid UserAuthenticateRequest request) {
        return authManagementService.login(request);
    }
}
