package com.market.helper.objectmodifier.impl;

import com.market.helper.objectmodifier.AccountObjectModifier;
import com.market.model.Account;
import org.springframework.stereotype.Component;

@Component
public class AccountObjectModifierImpl implements AccountObjectModifier {

    @Override
    public Account applyWithdrawal(Account account,
                                   Double balance,
                                   Integer quantity) {
        account.setBalance(account.getBalance() - (balance * quantity));
        return account;
    }
}
