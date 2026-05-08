package com.market.config.feignclient;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Component
public class FeignClientConfig implements RequestInterceptor {

    @Override
    public void apply(RequestTemplate template) {
        template.header("X-Request-ID", getHeader("X-Request-Id"));
        template.header("Authorization", getHeader("Authorization"));
    }

    private String getHeader(String headerName) {
        var attributes = RequestContextHolder.getRequestAttributes();
        if (attributes instanceof ServletRequestAttributes) {
            var request = ((ServletRequestAttributes) attributes).getRequest();
            return request.getHeader(headerName);
        } else return null;
    }
}
