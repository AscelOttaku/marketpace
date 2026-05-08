package com.security.service.domain.impl;

import com.security.exceptions.EntityNotFoundException;
import com.security.helper.common.MessageSourceHelper;
import com.security.model.AuthUserDetails;
import com.security.model.User;
import com.security.repository.UserRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserDetailServiceImpl implements UserDetailsService {

    ModelMapper mapper;
    UserRepository repository;
    MessageSourceHelper messageSourceHelper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var user = repository.findByEmail(username)
                .map(userEntity -> mapper.map(userEntity, User.class))
                .orElseThrow(() -> new EntityNotFoundException(
                        messageSourceHelper.get("user.friendly.name", username),
                        messageSourceHelper.get("not.found.by.user.email.message", username)));
        return new AuthUserDetails(user);
    }
}
