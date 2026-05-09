package com.market.helper.objectcreator;

import com.market.dto.response.common.Response;
import com.market.model.Purchase;
import org.springframework.http.ResponseEntity;

public interface PurchaseObjectCreator extends ObjectCreator {

    ResponseEntity<Response> createSuccessResponse(Purchase purchase);
}
