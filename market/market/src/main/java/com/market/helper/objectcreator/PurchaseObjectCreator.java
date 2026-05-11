package com.market.helper.objectcreator;

import com.market.dto.request.purchase.PurchaseSaveRequest;
import com.market.dto.response.common.PagingContent;
import com.market.dto.response.common.Response;
import com.market.model.Product;
import com.market.model.Purchase;
import com.market.model.User;
import org.springframework.http.ResponseEntity;

public interface PurchaseObjectCreator extends ObjectCreator {

    ResponseEntity<Response> createSuccessResponse(Purchase purchase);

    ResponseEntity<Response> createPurchasesResponse(PagingContent<Purchase> purchases);

    Purchase createSaveModel(PurchaseSaveRequest request, Product product, User user);
}
