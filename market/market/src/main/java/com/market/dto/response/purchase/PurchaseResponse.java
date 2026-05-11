package com.market.dto.response.purchase;

import com.market.dto.response.product.ProductResponse;
import com.market.dto.response.user.UserResponse;
import com.market.enums.PurchaseStatus;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.FieldDefaults;
import lombok.experimental.SuperBuilder;

import java.time.LocalDateTime;

@Getter
@Setter
@SuperBuilder
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class PurchaseResponse {
    Long id;
    Double price;
    UserResponse user;
    Integer quantity;
    PurchaseStatus status;
    ProductResponse product;
    LocalDateTime createdAt;
    LocalDateTime updatedAt;
}
