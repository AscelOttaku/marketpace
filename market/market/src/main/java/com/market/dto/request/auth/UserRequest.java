package com.market.dto.request.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.FieldDefaults;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@SuperBuilder
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class UserRequest {

    @NotBlank(message = "поле 'name' обязательна")
    @Pattern(regexp = "^[\\u0400-\\u04FF]+$",
            message = "поле должно содержать только кириллические буквы без пробелов")
    String name;

    @NotBlank(message = "поле 'surname' обязательна")
    @Pattern(regexp = "^[\\u0400-\\u04FF]+$",
            message = "поле 'surname' должно содержать только кириллические буквы без пробелов")
    String surname;

    @Size(min = 1, max = 100, message = "поле 'patronymic' должно быть от 1 до 100 символов")
    @Pattern(regexp = "^[\\u0400-\\u04FF]+$",
            message = "поле 'patronymic' должно содержать только кириллические буквы без пробелов")
    String patronymic;
}
