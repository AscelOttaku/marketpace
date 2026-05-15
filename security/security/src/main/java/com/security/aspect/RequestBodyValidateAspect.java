package com.security.aspect;

import com.security.helper.other.ErrorsBuilder;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.stereotype.Component;
import org.springframework.validation.BindingResult;

@Aspect
@Component
public class RequestBodyValidateAspect {

    @Pointcut("execution(* com.security.api.*.*(.., @com.security.annotation.RequestBodyValidate (*), ..))")
    public void requestBodyValidatePointcut() {
    }

    @Before("requestBodyValidatePointcut()")
    public void validateRequestBody(JoinPoint jp) {
        BindingResult bindingResult = null;
        for (var arg : jp.getArgs()) {
            if (arg instanceof BindingResult) {
                bindingResult = (BindingResult) arg;
                break;
            }
        }
        ErrorsBuilder.buildError(bindingResult);
    }
}
