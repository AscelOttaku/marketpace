package com.market.service.businesslogic;

import com.market.dto.request.auth.UserRegisterRequest;
import com.market.dto.request.auth.UserUpdateRequest;
import com.market.dto.response.common.Response;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;

public interface UserManagementService {
    ResponseEntity<Response> register(UserRegisterRequest request,
                                      BindingResult bindingResult);

    ResponseEntity<Response> update(UserUpdateRequest request,
                                    BindingResult bindingResult);
}
