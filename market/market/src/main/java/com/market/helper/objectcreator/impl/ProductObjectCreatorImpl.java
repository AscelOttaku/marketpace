package com.market.helper.objectcreator.impl;

import com.market.dto.request.product.ProductSaveRequest;
import com.market.dto.request.product.ProductUpdateRequest;
import com.market.dto.response.common.PagingContent;
import com.market.dto.response.common.Response;
import com.market.dto.response.product.ProductResponse;
import com.market.dto.response.user.UserResponse;
import com.market.enums.ProductStatus;
import com.market.helper.file.FileOperationHelper;
import com.market.helper.objectcreator.ProductObjectCreator;
import com.market.helper.other.PagingContentWrapper;
import com.market.model.Product;
import com.market.model.User;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public class ProductObjectCreatorImpl implements ProductObjectCreator {

    @Override
    public Product createSaveModel(ProductSaveRequest request,
                                   byte[] img,
                                   User user) {
        return Product.builder()
                .name(request.getName())
                .description(request.getDescription())
                .price(request.getPrice())
                .img(img)
                .user(user)
                .status(ProductStatus.ACTIVE)
                .quantity(request.getQuantity())
                .build();
    }

    @Override
    public Product createUpdate(Product existing,
                                ProductUpdateRequest request,
                                byte[] img) {
        existing.setName(request.getName());
        existing.setDescription(request.getDescription());
        existing.setPrice(request.getPrice());
        if (img.length > 0) existing.setImg(img);
        existing.setQuantity(request.getQuantity());
        existing.setStatus(request.getStatus());
        return existing;
    }

    @Override
    public ResponseEntity<Response> createSuccessResponse(Product product) {
        return ResponseEntity.ok()
                .body(Response.builder()
                        .status(Response.Status.SUCCESS)
                        .data(ProductResponse.builder()
                                .id(product.getId())
                                .name(product.getName())
                                .description(product.getDescription())
                                .quantity(product.getQuantity())
                                .status(product.getStatus())
                                .price(product.getPrice())
                                .build())
                        .build());
    }

    @Override
    public ResponseEntity<byte[]> createImgResponse(Product product) {
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, FileOperationHelper.defineImgExtension(product.getImg()))
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "inline; filename=\"" + product.getName() + ".jpg\"")
                .body(product.getImg());
    }

    @Override
    public ResponseEntity<Response> createProductsResponse(PagingContent<Product> products) {
        return ResponseEntity.ok()
                .body(Response.builder()
                        .status(Response.Status.SUCCESS)
                        .data(PagingContent.<ProductResponse>builder()
                                .content(products.getContent().stream().map(this::mapProductResponse)
                                        .toList())
                                .page(products.getPage())
                                .size(products.getSize())
                                .totalPages(products.getTotalPages())
                                .totalElements(products.getTotalElements())
                                .hasNextPage(products.getHasNextPage())
                                .hasPreviousPage(products.getHasPreviousPage())
                                .build())
                        .build());
    }

    private ProductResponse mapProductResponse(Product product) {
        return ProductResponse.builder()
                .id(product.getId())
                .name(product.getName())
                .description(product.getDescription())
                .quantity(product.getQuantity())
                .status(product.getStatus())
                .price(product.getPrice())
                .user(UserResponse.builder()
                        .id(product.getUser().getId())
                        .email(product.getUser().getEmail())
                        .name(product.getUser().getName())
                        .surname(product.getUser().getSurname())
                        .patronymic(product.getUser().getPatronymic())
                        .msisdn(product.getUser().getMsisdn())
                        .build())
                .build();
    }
}
