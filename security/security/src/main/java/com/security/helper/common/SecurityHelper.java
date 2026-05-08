package com.security.helper.common;

import com.security.model.AuthUserDetails;
import com.security.model.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityHelper {

    private SecurityHelper() {
    }

    private static Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    public static User getAuthenticatedUser() {
        return ((AuthUserDetails) getAuthentication()
                .getPrincipal())
                .user();
    }
}
