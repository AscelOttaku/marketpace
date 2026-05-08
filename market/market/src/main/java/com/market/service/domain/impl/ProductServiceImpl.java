package com.market.service.domain.impl;

import com.market.dto.response.common.PagingContent;
import com.market.entity.ProductEntity;
import com.market.exceptions.EntityNotFoundException;
import com.market.helper.common.MessageSourceHelper;
import com.market.helper.other.PagingContentWrapper;
import com.market.model.Product;
import com.market.repository.ProductRepository;
import com.market.service.domain.ProductService;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
public class ProductServiceImpl implements ProductService {
    ProductRepository repository;
    MessageSourceHelper messageSource;
    ModelMapper mapper;

    @Override
    public Product save(Product product) {
        var saved = repository.save(mapper.map(product, ProductEntity.class));
        return mapper.map(saved, Product.class);
    }

    @Override
    public Product update(Product product) {
        var entity = repository.findById(product.getId())
                .orElseThrow(() -> new EntityNotFoundException(
                        messageSource.get("not.found.by.product.id.message", product.getId())));
        mapper.map(product, entity);
        entity = repository.save(entity);
        return mapper.map(entity, Product.class);
    }

    @Override
    public Product findById(Long id) {
        return repository.findById(id)
                .map(productEntity -> mapper.map(productEntity, Product.class))
                .orElseThrow(() -> new EntityNotFoundException(
                        messageSource.get("not.found.by.product.id.message", id)));
    }

    @Override
    public PagingContent<Product> findAll(int page, int size, String search) {
        var pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        var products = repository.findAll(search, pageable)
                .map(productEntity -> mapper.map(productEntity, Product.class));
        return PagingContentWrapper.wrapPagingContent(products);
    }
}
