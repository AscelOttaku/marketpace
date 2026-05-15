package com.market.service.domain;

import com.market.enums.CatalogName;
import com.market.model.Catalog;

import java.util.List;

public interface CatalogService {
    Catalog save(Catalog catalog);

    Catalog findById(Long id);

    Catalog findByName(CatalogName catalogName);

    Catalog findOrCreateByName(CatalogName name);

    List<Catalog> findAll();
}
