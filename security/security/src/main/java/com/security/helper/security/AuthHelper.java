package com.security.helper.security;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

@Component
public class AuthHelper {
    private static final Map<Pattern, String> PUBLIC_PATHS =
            Map.of(Pattern.compile("^/auth/login$"), HttpMethod.POST.name());
    private static final List<String> REFRESH_PATHS =
            List.of("/auth/refresh", "/auth/validate/refresh", "/auth/password");

    public void authenticate(UserDetails userDetails) {
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userDetails,
                        userDetails.getPassword(), userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    public boolean isPathNotExampted(String requestPath, String method) {
        return PUBLIC_PATHS.entrySet().stream().noneMatch(entry ->
                entry.getKey().matcher(requestPath).matches() && entry.getValue().equals(method));
    }

    public boolean hasNotExistAuthHeader(String authHeader) {
        return authHeader == null || authHeader.isBlank() || !authHeader.startsWith("Bearer ");
    }

    public boolean isRefreshTokenRequest(String requestPath) {
        return REFRESH_PATHS.contains(requestPath);
    }
}
