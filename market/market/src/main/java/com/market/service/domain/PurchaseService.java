package com.market.service.domain;

import com.market.model.Purchase;

public interface PurchaseService {
    Purchase findById(Long id);
}
