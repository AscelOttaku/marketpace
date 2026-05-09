package com.market.helper.objectcreator.impl;

import com.market.dto.response.common.Response;
import com.market.dto.response.purchase.PurchaseResponse;
import com.market.helper.objectcreator.PurchaseObjectCreator;
import com.market.model.Purchase;
import org.modelmapper.ModelMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public class PurchaseObjectCreatorImpl implements PurchaseObjectCreator {

    ModelMapper mapper;

    @Override
    public ResponseEntity<Response> createSuccessResponse(Purchase purchase) {
        return ResponseEntity.ok()
                .body(Response.builder()
                        .status(Response.Status.SUCCESS)
                        .data(mapper.map(purchase, PurchaseResponse.class))
                        .build());
    }
}
