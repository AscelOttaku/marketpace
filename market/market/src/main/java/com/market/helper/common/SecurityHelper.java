package com.market.helper.common;

import com.market.model.AuthUserDetails;
import com.market.model.User;
import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityHelper {

    private SecurityHelper() {
    }

    public static User getAuthenticatedUser() {
        return ((AuthUserDetails)SecurityContextHolder.getContext().getAuthentication()
                .getPrincipal())
                .user();
    }

    public static Long getAuthenticatedUserUserId() {
        return ((AuthUserDetails)SecurityContextHolder.getContext().getAuthentication()
                .getPrincipal())
                .user()
                .getId();
    }
}
