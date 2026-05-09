package com.market.filter;

import com.market.helper.common.MessageSourceHelper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
@Component
@RequiredArgsConstructor
@Order(Ordered.HIGHEST_PRECEDENCE)
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class RequestLoggingFilter extends OncePerRequestFilter {

    MessageSourceHelper messageSourceHelper;

    @NonFinal
    @Value("${max.body.length}")
    int maxBodyLength;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        var requestCache = new ContentCachingRequestWrapper(request);
        var responseCache = new ContentCachingResponseWrapper(response);
        try {
            filterChain.doFilter(requestCache, responseCache);
        } finally {
            this.logRequest(requestCache, responseCache);
            responseCache.copyBodyToResponse();
        }
    }

    private void logRequest(ContentCachingRequestWrapper request,
                            ContentCachingResponseWrapper response) {
        var requestId = request.getHeader("X-Request-ID");
        var requestPath = request.getRequestURI();
        log.info(messageSourceHelper.get("incoming.request"), requestPath, request.getMethod(),
                request.getQueryString(), requestId);
        var requestBody = fetchBody(request.getContentAsByteArray());
        if (requestBody != null && isJson(request.getContentType()))
            log.info(messageSourceHelper.get("incoming.request.body"), requestBody);
        log.info(messageSourceHelper.get("outgoing.response"), response.getStatus(), requestId);
        var responseBody = fetchBody(response.getContentAsByteArray());
        if (responseBody != null && isJson(response.getContentType()))
            log.info(messageSourceHelper.get("outgoing.response.body"), responseBody);
    }

    private String fetchBody(byte[] content) {
        if (content.length == 0) return null;
        var length = Math.min(content.length, maxBodyLength);
        var body = new String(content, 0, length, StandardCharsets.UTF_8);
        if (length != content.length) body = body.concat("...[Truncated]");
        return body;
    }

    private boolean isJson(String contentType) {
        return contentType != null && contentType.startsWith("application/json");
    }
}


