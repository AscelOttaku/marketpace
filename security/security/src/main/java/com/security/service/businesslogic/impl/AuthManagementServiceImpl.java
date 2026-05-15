package com.security.service.businesslogic.impl;

import com.security.dto.request.auth.ChangePasswordRequest;
import com.security.dto.request.auth.UserAuthenticateRequest;
import com.security.dto.response.auth.UserDetailsResponse;
import com.security.dto.response.common.Response;
import com.security.helper.common.SecurityHelper;
import com.security.helper.objectcreator.AuthManagementObjectCreator;
import com.security.helper.security.JwtHelper;
import com.security.helper.validator.Validator;
import com.security.model.AuthUserDetails;
import com.security.service.businesslogic.AuthManagementService;
import com.security.service.domain.UserService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.validation.BindingResult;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthManagementServiceImpl implements AuthManagementService {

    JwtHelper jwtHelper;
    Validator validator;
    UserService userService;
    AuthenticationManager authenticationManager;
    AuthManagementObjectCreator authManagementObjectCreator;

    @Override
    public ResponseEntity<Response> login(UserAuthenticateRequest request) {
        var usernamePassword = new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword());
        var authDetails = (AuthUserDetails) authenticationManager.authenticate(usernamePassword).getPrincipal();
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

    @Override
    public ResponseEntity<UserDetailsResponse> validate() {
        var user = SecurityHelper.getAuthenticatedUser();
        return authManagementObjectCreator.createUserDetailsResponse(user);
    }

    @Override
    public ResponseEntity<Response> changePassword(ChangePasswordRequest request,
                                                   BindingResult bindingResult) {
        var user = SecurityHelper.getAuthenticatedUser();
        user.setPassword(request.getOldPassword());
        validator.validatePassword(user, bindingResult);
        var updateModel = authManagementObjectCreator.createUserUpdateModel(user, request);
        userService.update(updateModel);
        return authManagementObjectCreator.createSuccessResponse();
    }
}
