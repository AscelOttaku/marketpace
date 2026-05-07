package com.market.model;

import com.market.enums.AccountStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class Account {
    Long id;
    Double balance;
    User user;
    AccountStatus status;
    LocalDateTime createdAt;
    LocalDateTime updatedAt;
}
