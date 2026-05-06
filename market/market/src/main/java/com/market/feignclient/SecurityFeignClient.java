package com.market.feignclient;

import org.springframework.cloud.openfeign.FeignClient;

@FeignClient(name = "security")
public interface SecurityFeignClient {
}
