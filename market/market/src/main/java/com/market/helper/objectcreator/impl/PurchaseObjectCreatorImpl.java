package com.market.helper.objectcreator.impl;

import com.market.dto.response.common.Response;
import com.market.dto.response.product.ProductResponse;
import com.market.dto.response.purchase.PurchaseResponse;
import com.market.dto.response.user.UserResponse;
import com.market.helper.objectcreator.PurchaseObjectCreator;
import com.market.model.Product;
import com.market.model.Purchase;
import com.market.model.User;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public class PurchaseObjectCreatorImpl implements PurchaseObjectCreator {

    @Override
    public ResponseEntity<Response> createSuccessResponse(Purchase purchase) {
        return ResponseEntity.ok()
                .body(Response.builder()
                        .status(Response.Status.SUCCESS)
                        .data(PurchaseResponse.builder()
                                .id(purchase.getId())
                                .price(purchase.getPrice())
                                .status(purchase.getStatus())
                                .user(mapUserResponse(purchase.getUser()))
                                .product(mapProductResponse(purchase.getProduct()))
                                .createdAt(purchase.getCreatedAt())
                                .updatedAt(purchase.getUpdatedAt())
                                .build())
                        .build());
    }

    private ProductResponse mapProductResponse(Product product) {
        return ProductResponse.builder()
                .id(product.getId())
                .name(product.getName())
                .description(product.getDescription())
                .price(product.getPrice())
                .user(mapUserResponse(product.getUser()))
                .status(product.getStatus())
                .quantity(product.getQuantity())
                .build();
    }

    private UserResponse mapUserResponse(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .name(user.getName())
                .surname(user.getSurname())
                .patronymic(user.getPatronymic())
                .msisdn(user.getMsisdn())
                .email(user.getEmail())
                .build();
    }
}
