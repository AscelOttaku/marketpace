package com.security.service.domain;

import com.security.model.CustomUserDetails;
import com.security.model.User;

public interface UserService {
    User findByEmail(String email);

    CustomUserDetails loadByLogin(String email);
}
