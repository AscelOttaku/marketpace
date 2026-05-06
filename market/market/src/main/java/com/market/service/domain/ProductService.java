package com.market.service.domain;

import com.market.dto.response.common.PagingContent;
import com.market.model.Product;

public interface ProductService {
    Product save(Product product);

    Product findById(Long id);

    PagingContent<Product> findAll(int page, int size, String search);
}
