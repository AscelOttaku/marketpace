package com.security.api;

import com.security.annotation.RequestBodyValidate;
import com.security.dto.request.auth.ChangePasswordRequest;
import com.security.dto.request.auth.UserAuthenticateRequest;
import com.security.dto.response.auth.UserDetailsResponse;
import com.security.dto.response.common.Response;
import com.security.service.businesslogic.AuthManagementService;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

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

    @PostMapping("/refresh")
    public ResponseEntity<Response> refreshAccessToken() {
        return authManagementService.refreshToken();
    }

    @PostMapping({"/validate", "validate/refresh"})
    public ResponseEntity<UserDetailsResponse> validate() {
        return authManagementService.validate();
    }

    @PutMapping("/password")
    public ResponseEntity<Response> changePassword(@RequestBody @Valid @RequestBodyValidate
                                                   ChangePasswordRequest request,
                                                   BindingResult bindingResult) {
        return authManagementService.changePassword(request, bindingResult);
    }
}
