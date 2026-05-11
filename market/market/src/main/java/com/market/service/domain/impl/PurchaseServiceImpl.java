package com.market.service.domain.impl;

import com.market.dto.response.common.PagingContent;
import com.market.entity.PurchaseEntity;
import com.market.exceptions.EntityNotFoundException;
import com.market.helper.common.MessageSourceHelper;
import com.market.helper.other.PagingContentWrapper;
import com.market.model.Purchase;
import com.market.repository.PurchaseRepository;
import com.market.service.domain.PurchaseService;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
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

    @Override
    public PagingContent<Purchase> findAll(int page, int size) {
        var pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "updatedAt"));
        var purchases = repository.findAll(pageable)
                .map(purchaseEntity -> mapper.map(purchaseEntity, Purchase.class));
        return PagingContentWrapper.wrapPagingContent(purchases);
    }

    @Override
    public PagingContent<Purchase> findByUserId(Long userId, int page, int size) {
        var pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "updatedAt"));
        var purchases = repository.findByUserId(userId, pageable)
                .map(purchaseEntity -> mapper.map(purchaseEntity, Purchase.class));
        return PagingContentWrapper.wrapPagingContent(purchases);
    }

    @Override
    public Purchase save(Purchase purchase) {
        var entity = repository.save(mapper.map(purchase, PurchaseEntity.class));
        return mapper.map(entity, Purchase.class);
    }
}
