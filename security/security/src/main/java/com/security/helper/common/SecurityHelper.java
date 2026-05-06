package com.security.helper.common;

import com.security.model.CustomUserDetails;
import com.security.model.User;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.naming.AuthenticationException;

public class SecurityHelper {

    private SecurityHelper() {
    }

    private static Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    public static User getAuthenticatedUser() {
        return ((CustomUserDetails) getAuthentication()
                .getPrincipal())
                .user();
    }
}
