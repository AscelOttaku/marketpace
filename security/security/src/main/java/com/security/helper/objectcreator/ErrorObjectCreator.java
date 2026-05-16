package com.security.helper.objectcreator;

public interface ErrorObjectCreator extends ObjectCreator {
    String createAccessDeniedResponse(String message);

    String createUnauthorizedResponse(String message);
}
