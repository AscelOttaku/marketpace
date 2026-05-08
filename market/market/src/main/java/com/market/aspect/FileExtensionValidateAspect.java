package com.market.aspect;

import com.market.annotation.FileExtensionValidate;
import com.market.enums.ForbiddenFileExtensions;
import com.market.exceptions.FileExtensionValidationException;
import com.market.helper.common.MessageSourceHelper;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.Arrays;

@Aspect
@Component
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class FileExtensionValidateAspect {

    MessageSourceHelper messageSourceHelper;

    @Pointcut("execution(* com.market.api.*.*(.., @com.market.annotation.FileExtensionValidate (*), ..))")
    public void pointcut() {
    };

    @Before("pointcut()")
    public void validateFileExtension(JoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        Parameter[] parameters = method.getParameters();
        Object[] args = joinPoint.getArgs();

        for (int i = 0; i < parameters.length; i++) {
            var parameter = parameters[i];
            var annotation = parameter.getAnnotation(FileExtensionValidate.class);
            if (annotation == null) continue;
            var arg = args[i];
            if (arg instanceof MultipartFile file) {
                validate(file, annotation);
            }
        }
    }

    private void validate(MultipartFile file, FileExtensionValidate annotation) {
        var contentType = file.getContentType();
        if (contentType == null)
            throw new FileExtensionValidationException(messageSourceHelper.get("forbidden.file.extension"));

        var forbidden = Arrays.stream(annotation.forbidden())
                .map(ForbiddenFileExtensions::getExtension)
                .filter(contentType::startsWith)
                .findFirst();

        if (forbidden.isPresent())
            throw new FileExtensionValidationException(messageSourceHelper.get("forbidden.file.extension"));
    }
}
