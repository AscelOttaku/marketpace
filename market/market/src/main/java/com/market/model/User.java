package com.market.model;

import com.market.enums.UserRole;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class User {
    Long id;
    String name;
    String surname;
    String patronymic;
    String msisdn;
    String email;
    String password;
    UserRole role;
}
