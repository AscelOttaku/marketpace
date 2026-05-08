package com.market.service.domain;

import com.market.model.AuthUserDetails;
import com.market.model.User;

public interface UserService {
    AuthUserDetails loadByEmail(String email);

    User findByEmail(String email);

    User findByMsisdn(String msisdn);

    User findById(Long id);

    User save(User user);

    User update(User user);
}
