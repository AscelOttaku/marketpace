package com.market.service.businesslogic;

import com.market.dto.request.purchase.PurchaseSaveRequest;
import com.market.dto.response.common.Response;
import org.springframework.http.ResponseEntity;

public interface PurchaseManagementService {
    ResponseEntity<Response> findById(Long id);

    ResponseEntity<Response> findAll(int page, int size);

    ResponseEntity<Response> findByUserId(Long userId, int page, int size);

    ResponseEntity<Response> save(PurchaseSaveRequest request);
}
