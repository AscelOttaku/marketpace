package com.gateway.config.gateway;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

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

    @Bean
    public CorsWebFilter corsWebFilter() {
        var config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("*"));
        config.addAllowedMethod("*");
        config.addAllowedHeader("*");
        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return new CorsWebFilter(source);
    }
}
