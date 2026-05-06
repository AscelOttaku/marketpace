package com.market.dto.request.product;

import jakarta.validation.constraints.NotBlank;
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
public class ProductRequest {

    @NotBlank(message = "поле 'name' обязательна")
    String name;

    @NotBlank(message = "поле 'description' обязательна")
    String description;

    @NotNull(message = "поле 'price' обязательна")
    @Positive(message = "поле 'price' должно быть позитивным")
    Double price;
}
