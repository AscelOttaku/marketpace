package com.market.helper.objectcreator.impl;

import com.market.dto.request.auth.UserRegisterRequest;
import com.market.dto.request.auth.UserUpdateRequest;
import com.market.helper.objectcreator.UserManagementObjectCreator;
import com.market.model.Account;
import com.market.model.User;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
public class UserManagementObjectCreatorImpl implements UserManagementObjectCreator {
    PasswordEncoder passwordEncoder;

    @Override
    public User createUserSaveModel(UserRegisterRequest request) {
        return User.builder()
                .name(request.getName())
                .surname(request.getSurname())
                .patronymic(request.getPatronymic())
                .msisdn(request.getMsisdn())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();
    }

    @Override
    public User createUserUpdateModel(User existingUser, UserUpdateRequest request) {
        existingUser.setName(request.getName());
        existingUser.setSurname(request.getSurname());
        existingUser.setPatronymic(request.getPatronymic());
        return existingUser;
    }

    @Override
    public Account createAccountSaveModel(User user) {
        return Account.builder()
                .user(user)
                .balance(0.00)
                .build();
    }
}
