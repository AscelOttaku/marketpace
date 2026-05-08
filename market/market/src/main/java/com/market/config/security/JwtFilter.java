package com.market.config.security;

import com.market.helper.common.MessageSourceHelper;
import com.market.service.auth.AuthenticationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

@Slf4j
@Component
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class JwtFilter extends OncePerRequestFilter {
    private static final List<Map<Pattern, String>> PUBLIC_PATHS = List.of(
            Map.of(Pattern.compile("^/api/v1/users/register$"), HttpMethod.POST.name()));

    AuthenticationService authenticationService;
    MessageSourceHelper messageSourceHelper;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        String requestPath = request.getRequestURI();
        String method = request.getMethod();
        if (this.isPublicPath(requestPath, method)) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            authenticationService.authenticate();
        } catch (Exception e) {
            log.error(messageSourceHelper.get("auth.authentication.failed"), e.getMessage());
            handleJwtException(response);
            return;
        }
        filterChain.doFilter(request, response);
    }

    private boolean isPublicPath(String path, String method) {
        return PUBLIC_PATHS.stream().anyMatch(map ->
                map.entrySet().stream().anyMatch(entry ->
                        entry.getKey().matcher(path).matches() && entry.getValue().equals(method)));
    }

    private void handleJwtException(HttpServletResponse response) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
