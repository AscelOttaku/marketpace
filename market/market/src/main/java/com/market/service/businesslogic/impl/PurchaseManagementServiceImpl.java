package com.market.service.businesslogic.impl;

import com.market.dto.response.common.Response;
import com.market.helper.objectcreator.PurchaseObjectCreator;
import com.market.service.businesslogic.PurchaseManagementService;
import com.market.service.domain.PurchaseService;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
public class PurchaseManagementServiceImpl implements PurchaseManagementService {

    PurchaseService service;
    PurchaseObjectCreator objectCreator;

    @Override
    public ResponseEntity<Response> findById(Long id) {
        var purchase = service.findById(id);
        return objectCreator.createSuccessResponse(purchase);
    }
}
