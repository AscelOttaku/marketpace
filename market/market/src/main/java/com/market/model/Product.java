package com.market.model;

import com.market.enums.ProductStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class Product {
    Long id;
    String name;
    String description;
    Double price;
    User user;
    byte[] img;
    ProductStatus status;
    User buyer;
    Integer quantity;
}
