package com.market.helper.objectcreator.impl;

import com.market.helper.objectcreator.ErrorObjectCreator;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
public class ErrorObjectCreatorImpl implements ErrorObjectCreator {
}
