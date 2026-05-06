package com.market.api;

import com.market.dto.request.product.ProductSaveRequest;
import com.market.dto.request.product.ProductUpdateRequest;
import com.market.dto.response.common.Response;
import com.market.service.businesslogic.ProductManagementService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.naming.AuthenticationException;

@RestController
@RequestMapping("/api/v1/products")
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
public class ProductApi {

    ProductManagementService productManagementService;

    @GetMapping("view/img")
    public ResponseEntity<byte[]> viewImg(@RequestParam(name = "id") Long id) {
        return productManagementService.viewImg(id);
    }

    @PostMapping
    public ResponseEntity<Response> save(@ModelAttribute @Valid ProductSaveRequest request)
            throws AuthenticationException {
        return productManagementService.save(request);
    }

    @PutMapping
    public ResponseEntity<Response> update(@ModelAttribute @Valid ProductUpdateRequest request) {
        return productManagementService.update(request);
    }

    @GetMapping
    public ResponseEntity<Response> findById(@RequestParam(name = "id") Long id) {
        return productManagementService.findById(id);
    }

    @GetMapping("search")
    public ResponseEntity<Response> findAll(@RequestParam(defaultValue = "0") int page,
                                            @RequestParam(defaultValue = "15") int size,
                                            @RequestParam String search) {
        return productManagementService.findAll(page, size, search);
    }
}
