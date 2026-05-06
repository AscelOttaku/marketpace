package com.market.service.domain;

import com.market.model.CustomUserDetails;
import com.market.model.User;

public interface UserService {
    CustomUserDetails loadByEmail(String email);

    User findByEmail(String email);

    User findByMsisdn(String msisdn);

    User findById(Long id);

    User save(User user);
}
