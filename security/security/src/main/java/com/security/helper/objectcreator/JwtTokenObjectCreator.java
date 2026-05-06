package com.security.helper.objectcreator;

import com.security.model.User;
import io.jsonwebtoken.JwtParser;

import java.util.Date;

public interface JwtTokenObjectCreator extends ObjectCreator {
    String createAccessToken(User user, Date expiry);

    String createRefreshToken(User user, Date expiry);

    JwtParser createJwtParserForAccessToken();

    JwtParser createJwtParserForRefreshToken();
}
