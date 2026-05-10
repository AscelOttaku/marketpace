package com.market.feignclient;

import com.market.dto.response.auth.UserDetailsResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;

@FeignClient(name = "security-service")
public interface SecurityFeignClient {

    @PostMapping("/auth/validate")
    UserDetailsResponse validate();
}
