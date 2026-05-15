package com.market.helper.objectcreator;

import com.market.model.AuthUserDetails;
import com.market.model.User;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public interface AuthObjectCreator extends ObjectCreator {

    UsernamePasswordAuthenticationToken createAuthenticationToken(AuthUserDetails authUserDetails);

    AuthUserDetails createAuthUserDetails(User user);
}
