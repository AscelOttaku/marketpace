package com.market.helper.validator.domain;

import com.market.enums.AccountStatus;
import com.market.exceptions.ValidationException;
import com.market.helper.common.MessageSourceHelper;
import com.market.model.Account;
import com.market.model.Product;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
public class DomainValidator {

    MessageSourceHelper messageSourceHelper;

    public void validateAccount(Account account) {
        var errors = Stream.of(
                        account.getStatus() == AccountStatus.BLOCKED
                                ? messageSourceHelper.get("account.blocked", account.getId()) : null,
                        account.getBalance() < 0
                                ? messageSourceHelper.get("account.balance.negative", account.getId()) : null)
                .filter(Objects::nonNull)
                .collect(Collectors.joining(", "));

        if (!errors.isEmpty())
            throw new ValidationException(errors);
    }

    public void validateProduct(Product product) {
        var errors = Stream.of(product.getQuantity() < 0
                        ? messageSourceHelper.get("product.quantity.invalid", product.getId()) : null)
                .filter(Objects::nonNull)
                .collect(Collectors.joining(", "));
        if (!errors.isEmpty())
            throw new ValidationException(errors);
    }
}
