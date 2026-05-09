package com.market.api;

import com.market.dto.response.common.Response;
import com.market.service.businesslogic.PurchaseManagementService;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/purchases")
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
public class PurchaseApi {

    PurchaseManagementService purchaseManagementService;

    @GetMapping
    public ResponseEntity<Response> findById(@RequestParam(name = "id") Long id) {
        return purchaseManagementService.findById(id);
    }
}
