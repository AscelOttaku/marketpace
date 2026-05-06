package com.security.helper.security;

import com.security.model.CustomUserDetails;
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
    private static final List<Map<Pattern, String>> PUBLIC_PATHS = List.of(
            Map.of(Pattern.compile("^/auth/login$"), HttpMethod.POST.name()));

    public void authenticate(UserDetails userDetails) {
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userDetails,
                        userDetails.getPassword(), userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    public boolean isPathNotExampted(String requestPath, String method) {
        return PUBLIC_PATHS.stream().noneMatch(map ->
                map.entrySet().stream().anyMatch(entry ->
                        entry.getKey().matcher(requestPath).matches() && entry.getValue().equals(method)));
    }

    public boolean hasNotExistAuthHeader(String authHeader) {
        return authHeader == null || authHeader.isBlank() || !authHeader.startsWith("Bearer ");
    }

    public boolean isRefreshTokenRequest(String requestPath) {
        return requestPath.equals("/auth/refresh");
    }
}
