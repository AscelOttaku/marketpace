package com.market.model;

import com.market.enums.PurchaseStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class Purchase {
    Long id;
    Product product;
    Double price;
    User user;
    PurchaseStatus status;
    LocalDateTime createdAt;
    LocalDateTime updatedAt;
}
