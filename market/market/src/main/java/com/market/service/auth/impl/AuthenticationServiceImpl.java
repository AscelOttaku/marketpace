package com.market.service.auth.impl;

import com.market.helper.objectcreator.AuthObjectCreator;
import com.market.service.auth.AuthenticationService;
import com.market.service.domain.UserService;
import com.market.service.feignclient.SecurityFeignClient;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenticationServiceImpl implements AuthenticationService {

    SecurityFeignClient securityFeignClient;
    AuthObjectCreator authObjectCreator;
    UserService userService;

    @Override
    public void authenticate() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            var userDetailsResponse = securityFeignClient.validate();
            var user = userService.findByEmail(userDetailsResponse.getEmail());
            var userDetails = authObjectCreator.createAuthUserDetails(user);
            authentication = authObjectCreator.createAuthenticationToken(userDetails);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
    }
}
