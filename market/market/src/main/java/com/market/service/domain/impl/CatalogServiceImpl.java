package com.market.service.domain.impl;

import com.market.entity.CatalogEntity;
import com.market.enums.CatalogName;
import com.market.exceptions.EntityNotFoundException;
import com.market.helper.common.MessageSourceHelper;
import com.market.model.Catalog;
import com.market.repository.CatalogRepository;
import com.market.service.domain.CatalogService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class CatalogServiceImpl implements CatalogService {

    CatalogRepository repository;
    MessageSourceHelper messageSource;
    ModelMapper mapper;

    @Override
    public Catalog save(Catalog catalog) {
        var saved = repository.save(mapper.map(catalog, CatalogEntity.class));
        return mapper.map(saved, Catalog.class);
    }


    @Override
    public Catalog findById(Long id) {
        return repository.findById(id)
                .map(entity -> mapper.map(entity, Catalog.class))
                .orElseThrow(() -> new EntityNotFoundException(
                        messageSource.get("not.found.by.catalog.id.message", id)));
    }

    @Override
    public Catalog findByName(CatalogName catalog) {
        return repository.findByName(catalog)
                .map(entity -> mapper.map(entity, Catalog.class))
                .orElseThrow(() -> new EntityNotFoundException(
                        messageSource.get("not.found.by.catalog.name.message", catalog.getName())));
    }

    @Override
    public Catalog findOrCreateByName(CatalogName name) {
        return repository.findByName(name)
                .map(entity -> mapper.map(entity, Catalog.class))
                .orElseGet(() -> this.save(Catalog.builder()
                        .name(name)
                        .build()));
    }

    @Override
    public List<Catalog> findAll() {
        return repository.findAll().stream()
                .map(entity -> mapper.map(entity, Catalog.class))
                .toList();
    }
}
