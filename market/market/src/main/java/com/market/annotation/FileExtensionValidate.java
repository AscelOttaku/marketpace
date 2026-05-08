package com.market.annotation;

import com.market.enums.ForbiddenFileExtensions;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
public @interface FileExtensionValidate {
    ForbiddenFileExtensions[] forbidden();
}
