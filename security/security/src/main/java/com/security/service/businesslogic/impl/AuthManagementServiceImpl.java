package com.security.service.businesslogic.impl;

import com.security.dto.request.auth.UserAuthenticateRequest;
import com.security.dto.response.common.Response;
import com.security.helper.common.SecurityHelper;
import com.security.helper.objectcreator.AuthManagementObjectCreator;
import com.security.helper.security.JwtHelper;
import com.security.model.CustomUserDetails;
import com.security.service.businesslogic.AuthManagementService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthManagementServiceImpl implements AuthManagementService {

    JwtHelper jwtHelper;
    AuthenticationManager authenticationManager;
    AuthManagementObjectCreator authManagementObjectCreator;

    @Override
    public ResponseEntity<Response> login(UserAuthenticateRequest request) {
        var usernamePassword = new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword());
        var authDetails = (CustomUserDetails) authenticationManager.authenticate(usernamePassword).getPrincipal();
        String accessToken = jwtHelper.generateAccessToken(authDetails.user());
        String refreshToken = jwtHelper.generateRefreshToken(authDetails.user());
        return authManagementObjectCreator.createAuthenticateSuccessResponse(accessToken, refreshToken);
    }

    @Override
    public ResponseEntity<Response> refreshToken() {
        var user = SecurityHelper.getAuthenticatedUser();
        String accessToken = jwtHelper.generateAccessToken(user);
        return authManagementObjectCreator.createRefreshAccessTokenResponse(accessToken);
    }
}
