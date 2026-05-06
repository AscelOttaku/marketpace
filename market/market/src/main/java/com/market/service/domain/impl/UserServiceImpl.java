package com.market.service.domain.impl;

import com.market.entity.UserEntity;
import com.market.exceptions.EntityNotFoundException;
import com.market.helper.common.ResourceHelper;
import com.market.model.CustomUserDetails;
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
    ResourceHelper resourceHelper;
    ModelMapper mapper;

    @Override
    public CustomUserDetails loadByEmail(String email) {
        var user = findByEmail(email);
        return new CustomUserDetails(user);
    }

    @Override
    public User findByEmail(String email) {
        return repository.findByEmail(email)
                .map(userEntity -> mapper.map(userEntity, User.class))
                .orElseThrow(() -> new EntityNotFoundException(
                        resourceHelper.get("user.friendly.name", email),
                        resourceHelper.get("not.found.by.user.email.message", email)));
    }

    @Override
    public User findByMsisdn(String msisdn) {
        return repository.findByMsisdn(msisdn)
                .map(userEntity -> mapper.map(userEntity, User.class))
                .orElseThrow(() -> new EntityNotFoundException(
                        resourceHelper.get("user.friendly.name", msisdn),
                        resourceHelper.get("not.found.by.user.msisdn.message", msisdn)));
    }

    @Override
    public User findById(Long id) {
        return repository.findById(id)
                .map(userEntity -> mapper.map(userEntity, User.class))
                .orElseThrow(() -> new EntityNotFoundException(
                        resourceHelper.get("user.friendly.name", id),
                        resourceHelper.get("not.found.by.user.id.message", id)));
    }

    @Override
    public User save(User user) {
        UserEntity save = repository.save(mapper.map(user, UserEntity.class));
        return mapper.map(save, User.class);
    }
}
