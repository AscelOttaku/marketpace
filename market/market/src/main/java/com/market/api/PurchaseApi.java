package com.market.api;

import com.market.annotation.RequestBodyValidate;
import com.market.dto.request.purchase.PurchaseSaveRequest;
import com.market.dto.response.common.Response;
import com.market.service.businesslogic.PurchaseManagementService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

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

    @GetMapping("search")
    public ResponseEntity<Response> findAll(@RequestParam(defaultValue = "0") int page,
                                            @RequestParam(defaultValue = "15") int size) {
        return purchaseManagementService.findAll(page, size);
    }

    @GetMapping("user")
    public ResponseEntity<Response> findByUserId(@RequestParam(name = "userId") Long userId,
                                                 @RequestParam(defaultValue = "0") int page,
                                                 @RequestParam(defaultValue = "15") int size) {
        return purchaseManagementService.findByUserId(userId, page, size);
    }

    @PostMapping
    public ResponseEntity<Response> save(@RequestBody @Valid @RequestBodyValidate
                                         PurchaseSaveRequest request,
                                         BindingResult bindingResult) {
        return purchaseManagementService.save(request);
    }
}
