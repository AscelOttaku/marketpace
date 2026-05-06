package com.security.helper.security;

import com.security.helper.objectcreator.AuthManagementObjectCreator;
import com.security.helper.objectcreator.JwtTokenObjectCreator;
import com.security.helper.objectcreator.impl.AuthManagementObjectCreatorImpl;
import com.security.helper.objectcreator.impl.JwtTokenObjectCreatorImpl;
import com.security.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

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

    public String extractLogin(String token) {
        var jwtParser = jwtTokenObjectCreator.createJwtParser();
        var email = (String) jwtParser.parseClaimsJws(token)
                .getBody()
                .get(DATA);
        return encryptData.decrypt(email);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Генерация токена
     *
     * @param extraClaims дополнительные данные
     * @param userDetails данные пользователя
     * @return токен
     */
    private String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + Duration.ofDays(7).toMillis());
        return Jwts.builder().setClaims(extraClaims).setSubject(userDetails.getUsername())
                .setIssuedAt(now).setExpiration(expiryDate)
                .signWith(encryptData.getSigningKey(), encryptData.getSignature()).compact();
    }

    /**
     * Проверка токена на просроченность
     *
     * @param token токен
     * @return true, если токен просрочен
     */
    public boolean isTokenExpired(String token) {
        Date expiryDate = extractExpiration(token);
        return expiryDate.before(new Date());
    }

    /**
     * Извлечение данных из токена
     *
     * @param token           токен
     * @param claimsResolvers функция извлечения данных
     * @param <T>             тип данных
     * @return данные
     */
    private <T> T extractClaim(String token, Function<Claims, T> claimsResolvers) {
        final Claims claims = extractAllClaims(token);
        return claimsResolvers.apply(claims);
    }

    /**
     * Извлечение всех данных из токена
     *
     * @param token токен
     * @return данные
     */
    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(encryptData.getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Проверка токена на валидность
     *
     * @param token       токен
     * @param userDetails данные пользователя
     * @return true, если токен валиден
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String userName = extractLogin(token);
        return (userName.equals(userDetails.getUsername())) && isTokenExpired(token);
    }

    /**
     *
     * @param token токен
     * @return boolean результат проверки правильности подписи
     */
    public boolean isSignatureValid(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(encryptData.getSigningKey())
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}