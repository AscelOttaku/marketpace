package com.market.service.businesslogic.impl;

import com.market.dto.request.auth.UserRegisterRequest;
import com.market.dto.request.auth.UserUpdateRequest;
import com.market.dto.response.common.Response;
import com.market.helper.objectcreator.UserManagementObjectCreator;
import com.market.helper.validator.businesslogic.BusinessLogicValidator;
import com.market.model.User;
import com.market.service.businesslogic.UserManagementService;
import com.market.service.domain.AccountService;
import com.market.service.domain.UserService;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
public class UserManagementServiceImpl implements UserManagementService {
    UserService userService;
    AccountService accountService;
    BusinessLogicValidator businessLogicValidator;
    UserManagementObjectCreator userManagementObjectCreator;

    @Override
    @Transactional
    public ResponseEntity<Response> register(UserRegisterRequest request,
                                             BindingResult bindingResult) {
        var userRegisterModel = userManagementObjectCreator.createUserSaveModel(request);
        businessLogicValidator.validateUserUniqueness(userRegisterModel, bindingResult);
        User save = userService.save(userRegisterModel);
        var saveAccountModel = userManagementObjectCreator.createAccountSaveModel(save);
        accountService.save(saveAccountModel);
        return userManagementObjectCreator.createSuccessResponse();
    }

    @Override
    public ResponseEntity<Response> update(UserUpdateRequest request,
                                           BindingResult bindingResult) {
        var existingUser = userService.findById(request.getId());
        var userUpdateModel = userManagementObjectCreator.createUserUpdateModel(existingUser, request);
        businessLogicValidator.validateUserUniqueness(userUpdateModel, bindingResult);
        userService.update(userUpdateModel);
        return userManagementObjectCreator.createSuccessResponse();
    }
}
