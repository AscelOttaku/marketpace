package com.market.dto.response.product;

import com.market.dto.request.catalog.CatalogResponse;
import com.market.dto.response.user.UserResponse;
import com.market.enums.ProductStatus;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.FieldDefaults;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@SuperBuilder
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class ProductResponse {
    Long id;
    String name;
    String description;
    Double price;
    UserResponse user;
    ProductStatus status;
    Integer quantity;
    CatalogResponse catalog;
}
