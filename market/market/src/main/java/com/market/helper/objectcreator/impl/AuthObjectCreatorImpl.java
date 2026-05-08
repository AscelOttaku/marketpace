package com.market.helper.objectcreator.impl;

import com.market.helper.objectcreator.AuthObjectCreator;
import com.market.model.AuthUserDetails;
import com.market.model.User;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Component;

@Component
public class AuthObjectCreatorImpl implements AuthObjectCreator {

    @Override
    public UsernamePasswordAuthenticationToken createAuthenticationToken(AuthUserDetails authUserDetails) {
        return new UsernamePasswordAuthenticationToken(authUserDetails, authUserDetails.getPassword(),
                authUserDetails.getAuthorities());
    }

    @Override
    public AuthUserDetails createAuthUserDetails(User user) {
        return new AuthUserDetails(user);
    }
}
