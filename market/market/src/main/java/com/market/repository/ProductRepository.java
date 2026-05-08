package com.market.repository;

import com.market.entity.ProductEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface ProductRepository extends JpaRepository<ProductEntity, Long> {

    @Query("""
            SELECT p FROM ProductEntity p
            WHERE :search IS NULL
               OR TRIM(:search) = ''
               OR LOWER(p.name)        LIKE LOWER(CONCAT('%', :search, '%'))
               OR LOWER(p.description) LIKE LOWER(CONCAT('%', :search, '%'))
            ORDER BY CASE
               WHEN LOWER(p.name)        LIKE LOWER(CONCAT('%', :search, '%')) THEN 1
               WHEN LOWER(p.description) LIKE LOWER(CONCAT('%', :search, '%')) THEN 2
               ELSE 3
            END
            """)
    Page<ProductEntity> findAll(@Param("search") String search, Pageable pageable);
}
