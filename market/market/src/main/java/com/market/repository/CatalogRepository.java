package com.market.repository;

import com.market.entity.CatalogEntity;
import com.market.enums.CatalogName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CatalogRepository extends JpaRepository<CatalogEntity, Long> {
    Optional<CatalogEntity> findByName(CatalogName name);
}
