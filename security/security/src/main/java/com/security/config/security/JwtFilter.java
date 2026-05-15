package com.security.config.security;

import com.security.helper.common.MessageSourceHelper;
import com.security.helper.security.AuthHelper;
import com.security.helper.security.JwtHelper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String HEADER_NAME = "Authorization";
    public static final String X_REQUEST_ID = "X-Request-ID";
    private final JwtHelper jwtHelper;
    private final AuthHelper authHelper;
    private final UserDetailsService userDetailsService;
    private final MessageSourceHelper messageSource;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String requestPath = request.getRequestURI();
        log.info(messageSource.get("incoming.request"), request.getMethod(), requestPath,
                request.getQueryString(), request.getHeader(X_REQUEST_ID));
        if (authHelper.isPathNotExampted(requestPath, request.getMethod())) {
            String authHeader = request.getHeader(HEADER_NAME);
            if (authHelper.hasNotExistAuthHeader(authHeader)) {
                log.error(messageSource.get("auth.empty.header"));
                return;
            }

            String token = authHeader.substring(BEARER_PREFIX.length());
            var isRefreshToken = authHelper.isRefreshTokenRequest(requestPath);
            try {
                var email = jwtHelper.extractLogin(token, isRefreshToken);
                var authUserDetails = userDetailsService.loadUserByUsername(email);
                authHelper.authenticate(authUserDetails);
                filterChain.doFilter(request, response);
            } catch (Exception e) {
                handleJwtException(response, isRefreshToken, e.getMessage());
            } finally {
                log.info(messageSource.get("outgoing.response"), response.getStatus());
            }
        } else {
            filterChain.doFilter(request, response);
            log.info(messageSource.get("outgoing.response"), response.getStatus(),
                    request.getHeader(X_REQUEST_ID));
        }
    }

    private void handleJwtException(HttpServletResponse response,
                                    boolean isRefreshToken,
                                    String message) {
        log.error(messageSource.get(isRefreshToken ? "auth.jwt.refresh.token.incorrect" :
                "auth.jwt.access.token.incorrect"), message);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
