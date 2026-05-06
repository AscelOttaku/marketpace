package com.market.helper.objectcreator;

import com.market.dto.request.product.ProductSaveRequest;
import com.market.dto.request.product.ProductUpdateRequest;
import com.market.dto.response.common.Response;
import com.market.model.Product;
import com.market.model.User;
import org.springframework.http.ResponseEntity;

public interface ProductObjectCreator extends ObjectCreator{
    Product createSaveModel(ProductSaveRequest request,
                            byte[] img,
                            User user);

    Product createUpdate(Product existing,
                         ProductUpdateRequest request,
                         byte[] img);

    ResponseEntity<Response> createSuccessResponse(Product product);

    ResponseEntity<byte[]> createImgResponse(Product product);
}
