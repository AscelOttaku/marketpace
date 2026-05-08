package com.market.aspect;

import com.market.helper.other.ErrorsBuilder;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.stereotype.Component;
import org.springframework.validation.BindingResult;

@Aspect
@Component
public class RequestBodyValidateAspect {

    @Pointcut("execution(* com.market.api.*.*(.., @com.market.annotation.RequestBodyValidate (*), ..))")
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
