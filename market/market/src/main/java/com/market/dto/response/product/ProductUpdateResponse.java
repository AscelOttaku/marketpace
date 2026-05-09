package com.market.dto.response.product;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.FieldDefaults;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@SuperBuilder
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class ProductUpdateResponse extends ProductResponse{
}
