package com.security.helper.security;

import com.security.helper.objectcreator.JwtTokenObjectCreator;
import com.security.model.User;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.ZonedDateTime;
import java.util.Date;

import static com.security.helper.objectcreator.impl.JwtTokenObjectCreatorImpl.DATA;

@Component
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class JwtHelper {
    
    @NonFinal
    @Value("${access.token.expiration.date}")
    String accessTokenExpirationDate;
    @NonFinal
    @Value("${refresh.token.expiration.date}")
    String refreshTokenExpirationDate;

    EncryptData encryptData;
    JwtTokenObjectCreator jwtTokenObjectCreator;

    public String generateAccessToken(User user) {
        var expiry = Date.from(ZonedDateTime.now()
                .plusHours(Long.parseLong(accessTokenExpirationDate))
                .toInstant());
        return jwtTokenObjectCreator.createAccessToken(user, expiry);
    }

    public String generateRefreshToken(User user) {
        Date expiry = Date.from(ZonedDateTime.now()
                .plusHours(Long.parseLong(refreshTokenExpirationDate))
                .toInstant());
        return jwtTokenObjectCreator.createRefreshToken(user, expiry);
    }

    public String extractLogin(String token, boolean isRefreshToken) {
        var jwtParser = isRefreshToken ? jwtTokenObjectCreator.createJwtParserForRefreshToken() :
                jwtTokenObjectCreator.createJwtParserForAccessToken();
        var email = (String) jwtParser.parseClaimsJws(token)
                .getBody()
                .get(DATA);
        return encryptData.decrypt(email);
    }
}