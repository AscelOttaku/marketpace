package com.security.helper.common;

import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
public class MessageSourceHelper {

    MessageSource messageSource;

    public String get(String key, Object arg) {
        var message = messageSource.getMessage(key, null, LocaleContextHolder.getLocale());
        return String.format(message, arg);
    }

    public String get(String key, Object... args) {
        var message = messageSource.getMessage(key, null, LocaleContextHolder.getLocale());
        return String.format(message, args);
    }
}
