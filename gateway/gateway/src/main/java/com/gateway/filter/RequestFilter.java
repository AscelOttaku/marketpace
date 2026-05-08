package com.gateway.filter;

import com.gateway.helper.MessageSourceHelper;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class RequestFilter implements GlobalFilter, Ordered {

    MessageSourceHelper messageSourceHelper;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        var modifyExchange = this.modifyExchange(exchange);
        var request = modifyExchange.getRequest();
        this.logRequest(request);
        var requestPath = request.getPath().value();
        if (this.isPathExampted(requestPath)) return chain.filter(modifyExchange);
        var authHeader = request.getHeaders().getFirst("Authorization");
        if (this.hasNonExistingAuthHeader(authHeader)) {
            log.error(messageSourceHelper.get("auth.header.missing"));
            return errorResponse(modifyExchange);
        }
        var jwt = this.getJwtFromAuthHeader(authHeader);
        if (jwt.isBlank()) {
            log.error(messageSourceHelper.get("auth.header.missing"));
            return errorResponse(modifyExchange);
        }
        var response = modifyExchange.getResponse();
        return chain.filter(modifyExchange)
                .doOnTerminate(() -> log.info(messageSourceHelper.get("outgoing.response"),
                        response.getStatusCode()));
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    private boolean isPathExampted(String requestPath) {
        return requestPath.equals("/api/v1/users/register") ||
                requestPath.equals("/auth/login");
    }

    private ServerWebExchange modifyExchange(ServerWebExchange exchange) {
        var requestId = UUID.randomUUID().toString();
        var modifyExchange = exchange.getRequest().mutate()
                .header("X-Request-ID", requestId)
                .build();
        return exchange.mutate()
                .request(modifyExchange)
                .build();
    }

    private void logRequest(ServerHttpRequest request) {
        var requestPath = request.getPath().value();
        var requestId = request.getHeaders().getFirst("X-Request-ID");
        log.info(messageSourceHelper.get("incoming.request"), requestPath, request.getMethod(),
                request.getQueryParams(), requestId);
    }

    private boolean hasNonExistingAuthHeader(String authHeader) {
        return authHeader == null || !authHeader.startsWith("Bearer ");
    }

    private Mono<Void> errorResponse(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    private String getJwtFromAuthHeader(String authHeader) {
        return authHeader.substring(7);
    }
}
