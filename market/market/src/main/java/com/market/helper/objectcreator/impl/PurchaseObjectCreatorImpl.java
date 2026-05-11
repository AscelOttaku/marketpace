package com.market.helper.objectcreator.impl;

import com.market.dto.request.purchase.PurchaseSaveRequest;
import com.market.dto.response.common.PagingContent;
import com.market.dto.response.common.Response;
import com.market.dto.response.product.ProductResponse;
import com.market.dto.response.purchase.PurchaseResponse;
import com.market.dto.response.user.UserResponse;
import com.market.enums.PurchaseStatus;
import com.market.helper.objectcreator.PurchaseObjectCreator;
import com.market.model.Product;
import com.market.model.Purchase;
import com.market.model.User;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.modelmapper.ModelMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class PurchaseObjectCreatorImpl implements PurchaseObjectCreator {

    ModelMapper mapper;

    @Override
    public ResponseEntity<Response> createSuccessResponse(Purchase purchase) {
        return ResponseEntity.ok()
                .body(Response.builder()
                        .status(Response.Status.SUCCESS)
                        .data(mapPurchaseResponse(purchase))
                        .build());
    }

    @Override
    public ResponseEntity<Response> createPurchasesResponse(PagingContent<Purchase> purchases) {
        return ResponseEntity.ok()
                .body(Response.builder()
                        .status(Response.Status.SUCCESS)
                        .data(PagingContent.<PurchaseResponse>builder()
                                .content(purchases.getContent().stream()
                                        .map(this::mapPurchaseResponse)
                                        .toList())
                                .page(purchases.getPage())
                                .size(purchases.getSize())
                                .totalPages(purchases.getTotalPages())
                                .totalElements(purchases.getTotalElements())
                                .hasNextPage(purchases.getHasNextPage())
                                .hasPreviousPage(purchases.getHasPreviousPage())
                                .build())
                        .build());
    }

    @Override
    public Purchase createSaveModel(PurchaseSaveRequest request,
                                    Product product,
                                    User user) {
        return Purchase.builder()
                .price(request.getQuantity() * product.getPrice())
                .user(user)
                .product(product)
                .quantity(request.getQuantity())
                .status(PurchaseStatus.SUCCESS)
                .build();
    }

    private PurchaseResponse mapPurchaseResponse(Purchase purchase) {
        return PurchaseResponse.builder()
                .id(purchase.getId())
                .user(mapper.map(purchase.getUser(), UserResponse.class))
                .price(purchase.getPrice())
                .quantity(purchase.getQuantity())
                .status(purchase.getStatus())
                .product(mapper.map(purchase.getProduct(), ProductResponse.class))
                .createdAt(purchase.getCreatedAt())
                .updatedAt(purchase.getUpdatedAt())
                .build();
    }
}
