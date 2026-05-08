package com.market.service.domain.impl;

import com.market.entity.UserEntity;
import com.market.exceptions.EntityNotFoundException;
import com.market.helper.common.MessageSourceHelper;
import com.market.model.AuthUserDetails;
import com.market.model.User;
import com.market.repository.UserRepository;
import com.market.service.domain.UserService;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
public class UserServiceImpl implements UserService {
    UserRepository repository;
    MessageSourceHelper messageSource;
    ModelMapper mapper;

    @Override
    public AuthUserDetails loadByEmail(String email) {
        var user = findByEmail(email);
        return new AuthUserDetails(user);
    }

    @Override
    public User findByEmail(String email) {
        return repository.findByEmail(email)
                .map(userEntity -> mapper.map(userEntity, User.class))
                .orElseThrow(() -> new EntityNotFoundException(
                        messageSource.get("user.friendly.name", email),
                        messageSource.get("not.found.by.user.email.message", email)));
    }

    @Override
    public User findByMsisdn(String msisdn) {
        return repository.findByMsisdn(msisdn)
                .map(userEntity -> mapper.map(userEntity, User.class))
                .orElseThrow(() -> new EntityNotFoundException(
                        messageSource.get("user.friendly.name", msisdn),
                        messageSource.get("not.found.by.user.msisdn.message", msisdn)));
    }

    @Override
    public User findById(Long id) {
        return repository.findById(id)
                .map(userEntity -> mapper.map(userEntity, User.class))
                .orElseThrow(() -> new EntityNotFoundException(
                        messageSource.get("user.friendly.name"),
                        messageSource.get("not.found.by.user.id.message", id)));
    }

    @Override
    public User save(User user) {
        UserEntity save = repository.save(mapper.map(user, UserEntity.class));
        return mapper.map(save, User.class);
    }

    @Override
    public User update(User user) {
        var entity = repository.findById(user.getId())
                .orElseThrow(() -> new EntityNotFoundException(
                        messageSource.get("user.friendly.name", user.getEmail()),
                        messageSource.get("not.found.by.user.id.message", user.getId())));
        mapper.map(user, entity);
        entity = repository.save(entity);
        return mapper.map(entity, User.class);
    }
}
