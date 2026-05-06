package com.market.dto.request.product;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.FieldDefaults;
import org.springframework.web.multipart.MultipartFile;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class ProductSaveRequest extends ProductRequest {

    @NotNull(message = "поле 'quantity' обязательна")
    @Positive(message = "поле 'quantity' должно быть позитивным")
    Integer quantity;

    @NotNull(message = "'img' обязателен")
    MultipartFile img;
}
