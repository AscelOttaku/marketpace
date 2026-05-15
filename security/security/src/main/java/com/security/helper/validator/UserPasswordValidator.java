package com.security.helper.validator;

import com.security.helper.common.MessageSourceHelper;
import com.security.model.User;
import com.security.service.domain.UserService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

@Component
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserPasswordValidator implements Validator {

    UserService userService;
    PasswordEncoder passwordEncoder;
    MessageSourceHelper messageSourceHelper;

    @Override
    public boolean supports(Class<?> clazz) {
        return User.class.equals(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        var user = (User) target;
        var password = userService.findByEmail(user.getEmail()).getPassword();
        if (!passwordEncoder.matches(user.getPassword(), password))
            errors.rejectValue("oldPassword", "",
                            messageSourceHelper.get("password.incorrect.message"));
    }
}
