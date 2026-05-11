package com.market.dto.request.purchase;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
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
public class PurchaseSaveRequest extends PurchaseRequest {

    @NotNull(message = "поле 'quantity' является обязательным")
    @Min(value = 1, message = "количество не должно быть меньше 1")
    @Max(value = 100, message = "количество не должно превышать 100")
    Integer quantity;
}
