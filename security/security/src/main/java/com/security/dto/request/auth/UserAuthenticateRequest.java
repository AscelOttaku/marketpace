package com.security.dto.request.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class UserAuthenticateRequest {

    @NotBlank(message = "поле 'email' обязательна")
    @Email(message = "поле 'email' должно быть валидным")
    String email;

    @NotBlank(message = "поле 'password' обязательна")
    String password;
}
