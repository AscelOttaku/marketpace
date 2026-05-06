package com.security.config.security;

import com.security.helper.common.MessageSourceHelper;
import com.security.helper.security.AuthHelper;
import com.security.helper.security.JwtHelper;
import com.security.service.domain.UserService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String HEADER_NAME = "Authorization";
    private final JwtHelper jwtHelper;
    private final AuthHelper authHelper;
    private final UserService userService;
    private final MessageSourceHelper messageSource;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader(HEADER_NAME);
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(BEARER_PREFIX.length());
        if (jwtHelper.isTokenExpired(token) || !jwtHelper.isSignatureValid(token)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            var email = jwtHelper.extractLogin(token);
            UserDetails customUserDetails = userService.loadByLogin(email);
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            handleJwtException(e);
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
