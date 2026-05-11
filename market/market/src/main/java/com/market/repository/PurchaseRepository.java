package com.market.repository;

import com.market.entity.PurchaseEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PurchaseRepository extends JpaRepository<PurchaseEntity, Long> {
    Page<PurchaseEntity> findByUserId(Long userId, Pageable pageable);
}
