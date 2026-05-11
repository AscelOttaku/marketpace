package com.market.service.domain.impl;

import com.market.entity.AccountEntity;
import com.market.exceptions.EntityNotFoundException;
import com.market.helper.common.MessageSourceHelper;
import com.market.helper.objectmodifier.AccountObjectModifier;
import com.market.helper.validator.domain.DomainValidator;
import com.market.model.Account;
import com.market.repository.AccountRepository;
import com.market.service.domain.AccountService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AccountServiceImpl implements AccountService {

    ModelMapper mapper;
    DomainValidator validator;
    AccountRepository repository;
    AccountObjectModifier objectModifier;
    MessageSourceHelper messageSourceHelper;

    @Override
    public Account save(Account account) {
        AccountEntity save = mapper.map(account, AccountEntity.class);
        return mapper.map(repository.save(save), Account.class);
    }

    @Override
    public Account withdraw(Account account,
                            Double balance,
                            Integer quantity) {
        var modified = objectModifier.applyWithdrawal(account, balance, quantity);
        validator.validateAccount(modified);
        var save = mapper.map(account, AccountEntity.class);
        return mapper.map(repository.save(save), Account.class);
    }

    @Override
    public Account findById(Long id) {
        return repository.findById(id)
                .map(entity -> mapper.map(entity, Account.class))
                .orElseThrow(() -> new EntityNotFoundException(
                        messageSourceHelper.get("user.friendly.account.name"),
                        messageSourceHelper.get("not.found.by.account.id.message", id)));
    }

    @Override
    public Account findByUserId(Long userId) {
        return repository.findByUserId(userId)
                .map(entity -> mapper.map(entity, Account.class))
                .orElseThrow(() -> new EntityNotFoundException(
                        messageSourceHelper.get("user.friendly.account.name"),
                        messageSourceHelper.get("not.found.by.user.id.message", userId)));
    }
}
