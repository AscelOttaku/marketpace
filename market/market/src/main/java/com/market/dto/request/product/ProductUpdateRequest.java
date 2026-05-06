package com.market.dto.request.product;

import com.market.enums.ProductStatus;
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
public class ProductUpdateRequest extends ProductRequest {

    @NotNull(message = "поле 'id' обязательна")
    @Positive(message = "поле 'id' должно быть позитивным")
    Long id;

    ProductStatus status;
    Integer quantity;
    MultipartFile img;
}
