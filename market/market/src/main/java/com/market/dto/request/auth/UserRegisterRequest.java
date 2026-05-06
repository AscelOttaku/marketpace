package com.market.dto.request.auth;

import com.market.enums.UserRole;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.*;
import lombok.experimental.FieldDefaults;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@SuperBuilder
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class UserRegisterRequest extends UserRequest {

    @NotBlank(message = "поле 'msisdn' обязательна")
    @Pattern(regexp = "^996\\d{9}$",
            message = "поле 'msisdn' должно начинаться с 996 и содержать 12 цифр")
    String msisdn;

    @NotBlank(message = "поле 'email' обязательна")
    @Email(message = "поле 'email' должно быть валидным")
    String email;

    @NotBlank(message = "поле 'password' обязательна")
    String password;

    @NotNull(message = "поле 'role' обязательна")
    UserRole role;
}
