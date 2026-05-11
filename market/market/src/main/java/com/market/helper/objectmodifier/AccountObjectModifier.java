package com.market.helper.objectmodifier;

import com.market.model.Account;

public interface AccountObjectModifier {
    Account applyWithdrawal(Account account,
                            Double balance,
                            Integer quantity);
}
