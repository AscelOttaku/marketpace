package com.market.service.businesslogic.impl;

import com.market.dto.request.purchase.PurchaseSaveRequest;
import com.market.dto.response.common.Response;
import com.market.helper.common.SecurityHelper;
import com.market.helper.objectcreator.PurchaseObjectCreator;
import com.market.service.businesslogic.PurchaseManagementService;
import com.market.service.domain.AccountService;
import com.market.service.domain.ProductService;
import com.market.service.domain.PurchaseService;
import com.market.service.domain.UserService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
public class PurchaseManagementServiceImpl implements PurchaseManagementService {

    PurchaseService service;
    UserService userService;
    ProductService productService;
    AccountService accountService;
    PurchaseObjectCreator objectCreator;

    @Override
    public ResponseEntity<Response> findById(Long id) {
        var purchase = service.findById(id);
        return objectCreator.createSuccessResponse(purchase);
    }

    @Override
    public ResponseEntity<Response> findAll(int page, int size) {
        var purchases = service.findAll(page, size);
        return objectCreator.createPurchasesResponse(purchases);
    }

    @Override
    public ResponseEntity<Response> findByUserId(Long userId, int page, int size) {
        var purchases = service.findByUserId(userId, page, size);
        return objectCreator.createPurchasesResponse(purchases);
    }

    @Override
    @Transactional
    public ResponseEntity<Response> save(PurchaseSaveRequest request) {
        var user = userService.findById(SecurityHelper.getAuthenticatedUserUserId());
        var product = productService.findById(request.getProductId());
        var account = accountService.findByUserId(user.getId());
        accountService.withdraw(account, (product.getPrice() * product.getQuantity()));
        product = productService.takeProduct(product, request.getQuantity());
        var saveModel = objectCreator.createSaveModel(request, product, user);
        return objectCreator.createSuccessResponse(service.save(saveModel));
    }
}
