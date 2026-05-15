package com.market.service.domain;

import com.market.model.Account;

public interface AccountService {
    Account save(Account account);

    Account withdraw(Account account,
                     Double balance);

    Account findById(Long id);

    Account findByUserId(Long userId);
}
