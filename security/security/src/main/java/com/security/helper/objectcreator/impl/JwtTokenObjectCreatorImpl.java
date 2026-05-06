package com.security.helper.objectcreator.impl;

import com.security.helper.objectcreator.JwtTokenObjectCreator;
import com.security.helper.security.EncryptData;
import com.security.model.User;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class JwtTokenObjectCreatorImpl implements JwtTokenObjectCreator {
    private static final String SUBJECT_ACCESS_TOKEN = "Access token";
    private static final String SUBJECT_REFRESH_TOKEN = "Refresh token";
    public static final String ROLE = "role";
    public static final String DATA = "data";
    public static final String ISSUER = "security-service";

    EncryptData encryptData;

    @Override
    public String createAccessToken(User user, Date expiry) {
        return Jwts.builder()
                .setSubject(SUBJECT_ACCESS_TOKEN)
                .claim(ROLE, user.getRole().name())
                .claim(DATA, encryptData.encrypt(user.getEmail()))
                .setIssuedAt(new Date())
                .setExpiration(expiry)
                .signWith(encryptData.getSigningKey(), encryptData.getSignature())
                .setIssuer(ISSUER)
                .compact();
    }

    @Override
    public String createRefreshToken(User user, Date expiry) {
        return Jwts.builder()
                .setSubject(SUBJECT_REFRESH_TOKEN)
                .claim(ROLE, user.getRole().name())
                .claim(DATA, encryptData.encrypt(user.getEmail()))
                .setIssuedAt(new Date())
                .setExpiration(expiry)
                .signWith(encryptData.getSigningKey(), encryptData.getSignature())
                .setIssuer(ISSUER)
                .compact();
    }

    @Override
    public JwtParser createJwtParserForAccessToken() {
        return Jwts.parserBuilder()
                .setSigningKey(encryptData.getSigningKey())
                .requireSubject(SUBJECT_ACCESS_TOKEN)
                .requireIssuer(ISSUER)
                .build();
    }

    @Override
    public JwtParser createJwtParserForRefreshToken() {
        return Jwts.parserBuilder()
                .setSigningKey(encryptData.getSigningKey())
                .requireSubject(SUBJECT_REFRESH_TOKEN)
                .requireIssuer(ISSUER)
                .build();
    }
}
