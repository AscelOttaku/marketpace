package com.security.dto.response.auth;

import com.security.enums.UserRole;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Getter
@Setter
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserDetailsResponse {
    String email;
    UserRole role;
}
