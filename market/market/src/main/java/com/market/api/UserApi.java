package com.market.api;

import com.market.dto.request.auth.UserRegisterRequest;
import com.market.dto.request.auth.UserUpdateRequest;
import com.market.dto.response.common.Response;
import com.market.service.businesslogic.UserManagementService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
public class UserApi {
    UserManagementService userManagementService;

    @PostMapping("/register")
    public ResponseEntity<Response> register(@RequestBody @Valid UserRegisterRequest request,
                                             BindingResult bindingResult) {
        return userManagementService.register(request, bindingResult);
    }

    @PutMapping("/update")
    public ResponseEntity<Response> update(@RequestBody @Valid UserUpdateRequest request,
                                           BindingResult bindingResult) {
        return userManagementService.update(request, bindingResult);
    }
}
