package com.market.service.domain.impl;

import com.market.entity.AccountEntity;
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
    AccountRepository repository;
    ModelMapper mapper;

    @Override
    public Account save(Account account) {
        AccountEntity save = mapper.map(account, AccountEntity.class);
        return mapper.map(repository.save(save), Account.class);
    }
}
