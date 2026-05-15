package com.market.helper.objectcreator.impl;

import com.market.helper.objectcreator.AuthObjectCreator;
import com.market.model.AuthUserDetails;
import com.market.model.User;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
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
