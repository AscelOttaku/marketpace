package com.gateway.config.gateway;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayRoutingConfig {

    @Bean
    public RouteLocator routeLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("product-route", p -> p
                        .path("/*/products/**",
                                "/*/users/**",
                                "/*/purchases/**")
                        .uri("lb://market-service"))
                .route("auth-route", p -> p
                        .path("/auth/**")
                        .uri("lb://security-service"))
                .build();
    }
}
