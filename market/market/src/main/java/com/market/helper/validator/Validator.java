package com.market.helper.validator;

import com.market.helper.other.ErrorsBuilder;
import com.market.model.User;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.stereotype.Component;
import org.springframework.validation.BindingResult;

@Component
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
public class Validator {
    UserValidator userValidator;

    public void validateUserUniqueness(User user, BindingResult bindingResult) {
        userValidator.validate(user, bindingResult);
        ErrorsBuilder.buildError(bindingResult);
    }
}
