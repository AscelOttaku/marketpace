package com.market.helper.common;

import com.market.model.CustomUserDetails;
import com.market.model.User;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.naming.AuthenticationException;

public class SecurityHelper {

    private SecurityHelper() {
    }

    private static Authentication getAuthentication() throws AuthenticationException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() ||
                authentication instanceof AnonymousAuthenticationToken)
            throw new AuthenticationException();

        return authentication;
    }

    public static User getAuthenticatedUser() throws AuthenticationException {
        return ((CustomUserDetails) getAuthentication()
                .getPrincipal())
                .user();
    }
}
