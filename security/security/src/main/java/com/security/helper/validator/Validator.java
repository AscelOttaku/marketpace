package com.security.helper.validator;

import com.security.helper.other.ErrorsBuilder;
import com.security.model.User;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.stereotype.Component;
import org.springframework.validation.BindingResult;

@Component
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
public class Validator {

    UserPasswordValidator passwordValidator;

    public void validatePassword(User user, BindingResult bindingResult) {
        passwordValidator.validate(user, bindingResult);
        ErrorsBuilder.buildError(bindingResult);
    }
}
