package com.security.dto.request.auth;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.FieldDefaults;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class ChangePasswordRequest {

    @NotBlank(message = "поле 'oldPassword' обязательна")
    String oldPassword;

    @NotBlank(message = "поле 'newPassword' обязательна")
    String newPassword;
}
