package com.market.service.domain;

import com.market.dto.response.common.PagingContent;
import com.market.model.Purchase;

public interface PurchaseService {
    Purchase findById(Long id);

    PagingContent<Purchase> findAll(int page, int size);

    PagingContent<Purchase> findByUserId(Long userId, int page, int size);

    Purchase save(Purchase purchase);
}
