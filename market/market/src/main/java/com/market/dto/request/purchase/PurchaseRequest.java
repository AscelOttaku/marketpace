package com.market.dto.request.purchase;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.FieldDefaults;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class PurchaseRequest {

    @NotNull(message = "поле 'productId' является обязательным")
    @Positive(message = "поле 'productId' должно быть положительным")
    Long productId;
}
