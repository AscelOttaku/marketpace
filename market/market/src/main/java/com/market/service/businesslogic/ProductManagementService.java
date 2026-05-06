package com.market.service.businesslogic;

import com.market.dto.request.product.ProductSaveRequest;
import com.market.dto.request.product.ProductUpdateRequest;
import com.market.dto.response.common.Response;
import org.springframework.http.ResponseEntity;

import javax.naming.AuthenticationException;

public interface ProductManagementService {
    ResponseEntity<Response> save(ProductSaveRequest request) throws AuthenticationException;

    ResponseEntity<Response> update(ProductUpdateRequest request);

    ResponseEntity<byte[]> viewImg(Long id);

    ResponseEntity<Response> findById(Long id);

    ResponseEntity<Response> findAll(int page, int size, String search);
}
