package com.market.service.domain.impl;

import com.market.exceptions.EntityNotFoundException;
import com.market.helper.common.MessageSourceHelper;
import com.market.model.Purchase;
import com.market.repository.PurchaseRepository;
import com.market.service.domain.PurchaseService;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
public class PurchaseServiceImpl implements PurchaseService {

    ModelMapper mapper;
    PurchaseRepository repository;
    MessageSourceHelper messageSourceHelper;

    @Override
    public Purchase findById(Long id) {
        return repository.findById(id)
                .map(purchaseEntity -> mapper.map(purchaseEntity, Purchase.class))
                .orElseThrow(() -> new EntityNotFoundException(
                        messageSourceHelper.get("not.found.by.purchase.id.message", id)));
    }
}
