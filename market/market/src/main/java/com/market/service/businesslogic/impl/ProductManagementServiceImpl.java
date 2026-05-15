package com.market.service.businesslogic.impl;

import com.market.dto.request.product.ProductSaveRequest;
import com.market.dto.request.product.ProductUpdateRequest;
import com.market.dto.response.common.Response;
import com.market.helper.common.SecurityHelper;
import com.market.helper.file.FileOperationHelper;
import com.market.helper.objectcreator.ProductObjectCreator;
import com.market.model.Catalog;
import com.market.service.businesslogic.ProductManagementService;
import com.market.service.domain.CatalogService;
import com.market.service.domain.ProductService;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import javax.naming.AuthenticationException;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
public class ProductManagementServiceImpl implements ProductManagementService {

    ProductService productService;
    CatalogService catalogService;
    ProductObjectCreator objectCreator;

    @Override
    public ResponseEntity<Response> save(ProductSaveRequest request) throws AuthenticationException {
        byte[] img = FileOperationHelper.readFile(request.getImg());
        var authUser = SecurityHelper.getAuthenticatedUser();
        Catalog catalog = catalogService.findOrCreateByName(request.getCatalogName());
        var saveModel = objectCreator.createSaveModel(request, img, authUser, catalog);
        var saved = productService.save(saveModel);
        return objectCreator.createSuccessResponse(saved);
    }

    @Override
    public ResponseEntity<Response> update(ProductUpdateRequest request) {
        var existing = productService.findById(request.getId());
        byte[] img = FileOperationHelper.readFile(request.getImg());
        var catalog = request.getCatalogName() == null ? null
                : catalogService.findOrCreateByName(request.getCatalogName());
        var updateModel = objectCreator.createUpdate(existing, request, img, catalog);
        var product = productService.save(updateModel);
        return objectCreator.createSuccessResponse(product);
    }

    @Override
    public ResponseEntity<byte[]> viewImg(Long id) {
        var product = productService.findById(id);
        return objectCreator.createImgResponse(product);
    }

    @Override
    public ResponseEntity<Response> findById(Long id) {
        var product = productService.findById(id);
        return objectCreator.createSuccessResponse(product);
    }

    @Override
    public ResponseEntity<Response> findAll(int page, int size, String search) {
        var products = productService.findAll(page, size, search);
        return objectCreator.createProductsResponse(products);
    }

    @Override
    public ResponseEntity<Response> findAllCatalogs() {
        var catalogs = catalogService.findAll();
        return objectCreator.createCatalogsResponse(catalogs);
    }
}
