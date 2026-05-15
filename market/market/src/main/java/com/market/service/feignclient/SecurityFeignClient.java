package com.market.service.feignclient;

import com.market.dto.response.auth.UserDetailsResponse;
import com.market.dto.response.common.Response;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;

@FeignClient(name = "security-service")
public interface SecurityFeignClient {

    @PostMapping("/auth/validate")
    UserDetailsResponse validate();

    @PostMapping("auth/validate/refresh")
    UserDetailsResponse validateRefresh();
}
