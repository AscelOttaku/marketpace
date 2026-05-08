package com.market.helper.validator;

import com.market.exceptions.EntityNotFoundException;
import com.market.helper.common.MessageSourceHelper;
import com.market.model.User;
import com.market.service.domain.UserService;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

@Component
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
public class UserValidator implements Validator {
    UserService userService;
    MessageSourceHelper messageSource;

    @Override
    public boolean supports(Class<?> clazz) {
        return User.class.equals(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        User request = (User) target;
        try {
            var byEmail = userService.findByEmail(request.getEmail());
            if (!byEmail.getId().equals(request.getId()))
                errors.rejectValue("email", "",
                        messageSource.get("already.exists.by.email", request.getEmail()));
        } catch (EntityNotFoundException ignored) {}

        try {
            var byMsisdn = userService.findByMsisdn(request.getMsisdn());
            if (!byMsisdn.getId().equals(request.getId()))
                errors.rejectValue("msisdn", "",
                        messageSource.get("already.exists.by.msisdn", request.getMsisdn()));
        } catch (EntityNotFoundException ignored) {}
    }
}
