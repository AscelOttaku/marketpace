package com.market.config.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String HEADER_NAME = "Authorization";

    private static final List<Map<Pattern, String>> PUBLIC_PATHS = List.of(
            Map.of(Pattern.compile("^/api/v1/users/register$"), HttpMethod.POST.name()));

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        String authHeader = request.getHeader(HEADER_NAME);
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        if (!this.isPublicPath(request.getRequestURI(), request.getMethod())) {
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean isPublicPath(String path, String method) {
        return PUBLIC_PATHS.stream().anyMatch(map ->
                map.entrySet().stream().anyMatch(entry ->
                        entry.getKey().matcher(path).matches() && entry.getValue().equals(method)));
    }
}
