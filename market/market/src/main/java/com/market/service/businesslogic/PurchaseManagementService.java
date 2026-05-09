package com.market.service.businesslogic;

import com.market.dto.response.common.Response;
import org.springframework.http.ResponseEntity;

public interface PurchaseManagementService {
    ResponseEntity<Response> findById(Long id);
}
