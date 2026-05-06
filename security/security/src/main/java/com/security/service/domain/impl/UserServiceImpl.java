package com.security.service.domain.impl;

import com.security.exceptions.EntityNotFoundException;
import com.security.helper.common.MessageSourceHelper;
import com.security.model.CustomUserDetails;
import com.security.model.User;
import com.security.repository.UserRepository;
import com.security.service.domain.UserService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserServiceImpl implements UserService {

    UserRepository repository;
    ModelMapper mapper;
    MessageSourceHelper messageSourceHelper;

    @Override
    public User findByEmail(String email) {
        return repository.findByEmail(email)
                .map(userEntity -> mapper.map(userEntity, User.class))
                .orElseThrow(() -> new EntityNotFoundException(
                        messageSourceHelper.get("user.friendly.name", email),
                        messageSourceHelper.get("not.found.by.user.email.message", email)));
    }

    @Override
    public CustomUserDetails loadByLogin(String email) {
        return new CustomUserDetails(findByEmail(email));
    }
}
