package com.market.dto.request.catalog;

import com.market.enums.CatalogName;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class CatalogResponse {
    Long id;
    CatalogName name;
}
